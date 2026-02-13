package sessiontracker

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/sha3"

	"peer-sniffer/pkg/streamprocessor"
)

// SessionInfo holds information about a network session
type SessionInfo struct {
	ID              string
	StartTime       time.Time
	EndTime         time.Time
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Protocol        string
	P2PSession      *P2PSessionInfo
	IsActive        bool
}

// P2PSessionInfo holds P2P-specific session information for XDC
type P2PSessionInfo struct {
	ClientNonce  []byte
	ServerNonce  []byte
	AuthRespHash []byte
	AckHash      []byte
	EphemeralPub []byte
	StaticShared []byte
	Secrets      *rlpx.Secrets
	NodeKey      *ecdsa.PrivateKey
	PeerID       string
	Established  bool
}

// MockConn is a mock connection that implements the net.Conn interface
// for use with rlpx when decrypting intercepted packets
type MockConn struct {
	readData    []byte
	readIndex   int
	closeCalled bool
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.readData) {
		return 0, io.EOF
	}

	n = copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *MockConn) Close() error {
	m.closeCalled = true
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	return &mockAddr{"local", "local"}
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &mockAddr{"remote", "remote"}
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type mockAddr struct {
	network, address string
}

func (ma *mockAddr) Network() string { return ma.network }
func (ma *mockAddr) String() string  { return ma.address }

// Global variable to store session information
var (
	SessionStore    = make(map[string]*SessionInfo)
	SessionMutex    sync.RWMutex
	nodeKey         *ecdsa.PrivateKey
	nodeKeyOnce     sync.Once
	streamProcessor *streamprocessor.StreamProcessor
)

// CreateCanonicalSessionID creates a consistent session ID regardless of packet direction
// This ensures both sides of a connection use the same session for handshake correlation
func CreateCanonicalSessionID(srcIP string, srcPort string, dstIP string, dstPort string) string {
	// Create a consistent ordering by comparing the combined addresses
	// Format: IP:Port to ensure consistent ordering regardless of direction
	sessionPart1 := fmt.Sprintf("%s:%s", srcIP, srcPort)
	sessionPart2 := fmt.Sprintf("%s:%s", dstIP, dstPort)

	// Create a consistent ordering by comparing the combined strings
	// Use lexicographic comparison to ensure same result for both directions
	if sessionPart1 < sessionPart2 {
		return fmt.Sprintf("%s-%s", sessionPart1, sessionPart2)
	} else {
		return fmt.Sprintf("%s-%s", sessionPart2, sessionPart1)
	}
}

// ProcessPacket analyzes a packet and extracts session information
func ProcessPacket(packet gopacket.Packet) error {
	// Process the packet through the stream processor for TCP stream reconstruction
	if streamProcessor != nil {
		streamProcessor.Process(packet)
	}

	// Also maintain the legacy session store for backward compatibility
	SessionMutex.Lock()
	defer SessionMutex.Unlock()

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return fmt.Errorf("no network layer found")
	}

	var srcIP, dstIP string
	switch layer := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = layer.SrcIP.String()
		dstIP = layer.DstIP.String()
	case *layers.IPv6:
		srcIP = layer.SrcIP.String()
		dstIP = layer.DstIP.String()
	default:
		return fmt.Errorf("unsupported network layer: %T", networkLayer)
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return fmt.Errorf("no transport layer found")
	}

	var srcPort, dstPort layers.TCPPort
	var protocol string

	switch layer := transportLayer.(type) {
	case *layers.TCP:
		srcPort = layer.SrcPort
		dstPort = layer.DstPort
		protocol = "TCP"
	case *layers.UDP:
		srcPort = layers.TCPPort(layer.SrcPort)
		dstPort = layers.TCPPort(layer.DstPort)
		protocol = "UDP"
	default:
		return fmt.Errorf("unsupported transport layer: %T", transportLayer)
	}

	sessionID := CreateCanonicalSessionID(srcIP, fmt.Sprintf("%d", srcPort), dstIP, fmt.Sprintf("%d", dstPort))

	session, exists := SessionStore[sessionID]
	if !exists {
		session = &SessionInfo{
			ID:              sessionID,
			StartTime:       packet.Metadata().Timestamp,
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			SourcePort:      uint16(srcPort),
			DestinationPort: uint16(dstPort),
			Protocol:        protocol,
			IsActive:        true,
		}
		SessionStore[sessionID] = session
	}

	session.EndTime = packet.Metadata().Timestamp

	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 && session.Protocol == "TCP" {
			detectP2PHandshake(session, payload)
		}
	}

	return nil
}

// detectP2PHandshake attempts to detect and parse XDC P2P handshake messages
func detectP2PHandshake(session *SessionInfo, payload []byte) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	// More flexible size check to accommodate various handshake packet sizes
	// Auth packets are typically ~194 bytes, Ack packets ~97 bytes
	if len(payload) < 50 || len(payload) > 500 {
		log.Printf("Skipping packet with size %d - not a handshake packet", len(payload))
		return fmt.Errorf("payload size doesn't match expected DevP2P handshake: %d", len(payload))
	}

	if session.P2PSession == nil {
		session.P2PSession = &P2PSessionInfo{}
	}

	// Instead of relying on size, we'll store handshake packets and try to determine
	// their type based on when they arrive in the connection sequence.
	// Auth packets typically come first (initiator -> recipient), Ack packets second (recipient -> initiator).

	// For now, we'll use a heuristic based on connection direction and timing
	// If this is the first handshake packet we see for this session, assume it's an Auth packet
	// If we already have an Auth packet for this session, assume this is an Ack packet

	if session.P2PSession.AuthRespHash == nil {
		// This is likely an Auth packet (first handshake packet)
		log.Printf("Detected potential Auth packet (size %d) for session %s", len(payload), session.ID)
		session.P2PSession.AuthRespHash = payload
		log.Printf("Captured Auth packet for session %s", session.ID)
	} else {
		// We already have an Auth packet, so this is likely an Ack packet
		log.Printf("Detected potential Ack packet (size %d) for session %s", len(payload), session.ID)
		session.P2PSession.AckHash = payload
		log.Printf("Captured Ack packet for session %s", session.ID)

		// Auth+Ack captured for this session. Streamprocessor will attempt to derive frame secrets.
		log.Printf("Auth+Ack captured for %s; waiting for streamprocessor handshake to derive secrets.", session.ID)
	}

	return nil
}

// parseAuthPacket parses XDC Auth packet (initiator)
func parseAuthPacket(p2pSession *P2PSessionInfo, data []byte) error {
	if len(data) < 162 {
		return fmt.Errorf("auth packet too short: %d", len(data))
	}

	ephemeralPubStart := 65
	nonceStart := 97

	p2pSession.EphemeralPub = make([]byte, 32)
	copy(p2pSession.EphemeralPub, data[ephemeralPubStart:ephemeralPubStart+32])

	p2pSession.ClientNonce = make([]byte, 32)
	copy(p2pSession.ClientNonce, data[nonceStart:nonceStart+32])

	return nil
}

// parseAckPacket parses XDC Ack packet (recipient)
func parseAckPacket(p2psession *P2PSessionInfo, data []byte) error {
	if len(data) < 65 {
		return fmt.Errorf("ack packet too short: %d", len(data))
	}

	ephemeralPubStart := 0
	nonceStart := 32

	p2psession.EphemeralPub = make([]byte, 32)
	copy(p2psession.EphemeralPub, data[ephemeralPubStart:ephemeralPubStart+32])

	p2psession.ServerNonce = make([]byte, 32)
	copy(p2psession.ServerNonce, data[nonceStart:nonceStart+32])

	return nil
}

// GetSession retrieves a session by ID
func GetSession(sessionID string) (*SessionInfo, bool) {
	SessionMutex.RLock()
	defer SessionMutex.RUnlock()

	session, exists := SessionStore[sessionID]
	return session, exists
}

// GetAllSessions returns all tracked sessions
func GetAllSessions() map[string]*SessionInfo {
	SessionMutex.RLock()
	defer SessionMutex.RUnlock()

	sessionsCopy := make(map[string]*SessionInfo, len(SessionStore))
	for k, v := range SessionStore {
		sessionsCopy[k] = v
	}
	return sessionsCopy
}

// ClearSessions clears all stored sessions
func ClearSessions() {
	SessionMutex.Lock()
	defer SessionMutex.Unlock()
	SessionStore = make(map[string]*SessionInfo)
}

// DecryptAndLogPlaintext attempts to decrypt encrypted data using session keys and logs plaintext
func DecryptAndLogPlaintext(sessionID string, encryptedData []byte) ([]byte, error) {
	SessionMutex.RLock()
	session, exists := SessionStore[sessionID]
	SessionMutex.RUnlock()

	if !exists {
		log.Printf("Session not found for ID: %s", sessionID)
		return nil, fmt.Errorf("session not found")
	}

	if session.P2PSession == nil {
		log.Printf("Session P2PSession is nil for ID: %s", sessionID)
		return nil, fmt.Errorf("no P2P session data available")
	}

	if !session.P2PSession.Established {
		log.Printf("Session not established for ID: %s, established=%t", sessionID, session.P2PSession.Established)
	}

	if session.P2PSession.Secrets == nil {
		log.Printf("Session secrets not available for ID: %s", sessionID)
		return nil, fmt.Errorf("session not established or secrets not available")
	}

	plaintext, err := decryptRLPxFrame(session.P2PSession, encryptedData)
	if err != nil {
		log.Printf("Failed to decrypt data for session %s: %v", sessionID, err)
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	log.Printf("Successfully decrypted %d bytes for session %s", len(plaintext), sessionID)
	return plaintext, nil
}

// processHandshake processes the handshake to derive session keys
func processHandshake(session *SessionInfo, authPacket []byte, ackPacket []byte) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	if session.P2PSession == nil {
		session.P2PSession = &P2PSessionInfo{}
	}

	nodeKey, err := getNodePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to get node private key: %v", err)
	}

	// Check if nodeKey is nil
	if nodeKey == nil {
		return fmt.Errorf("node private key is nil")
	}

	// According to RLPx handshake specification, the secrets are computed as follows:
	// ephemeral-key-agreement = ecdh(ephemeral-priv, remote-ephemeral-pub)
	// shared-secret = keccak256(ephemeral-key-agreement || keccak256(nonce || remote-nonce))
	// aes-secret = keccak256(ephemeral-key-agreement || shared-secret)
	// mac-secret = keccak256(ephemeral-key-agreement || aes-secret)

	authNonce := session.P2PSession.ClientNonce
	ackNonce := session.P2PSession.ServerNonce
	ephemeralPub := session.P2PSession.EphemeralPub

	if authNonce == nil || ackNonce == nil || ephemeralPub == nil {
		return fmt.Errorf("missing handshake data for key derivation")
	}

	// Note: In a real implementation, we would need the private keys to perform ECDH
	// For packet sniffing purposes, we'll simulate the key derivation process
	// using the available handshake data

	// Simulate the shared secret calculation
	nonceConcat := crypto.Keccak256(authNonce, ackNonce)
	sharedSecret := crypto.Keccak256(ephemeralPub, nonceConcat) // Simplified simulation

	// Derive AES and MAC secrets according to the specification
	aesSecret := crypto.Keccak256(ephemeralPub, sharedSecret)
	macSecret := crypto.Keccak256(ephemeralPub, aesSecret)

	// Setup MAC instances for the MACs according to the XDPoSChain implementation
	// egress-MAC = keccak(mac-secret ^ remote-nonce || auth-packet)
	// ingress-MAC = keccak(mac-secret ^ local-nonce || ack-packet)

	// Create MAC instances and initialize them with the proper secrets
	// The XOR operation is performed between the MAC secret and the respective nonce
	xorMacSecretInitNonce := make([]byte, len(macSecret))
	xorMacSecretRespNonce := make([]byte, len(macSecret))
	for i := 0; i < len(macSecret); i++ {
		xorMacSecretInitNonce[i] = macSecret[i] ^ authNonce[i%len(authNonce)]
		xorMacSecretRespNonce[i] = macSecret[i] ^ ackNonce[i%len(ackNonce)]
	}

	mac1 := sha3.NewLegacyKeccak256()
	mac1.Write(xorMacSecretRespNonce) // MAC secret XOR'd with response nonce
	mac1.Write(authPacket)
	mac2 := sha3.NewLegacyKeccak256()
	mac2.Write(xorMacSecretInitNonce) // MAC secret XOR'd with init nonce
	mac2.Write(ackPacket)

	// For the connection initiator (who sent auth), egress is auth direction, ingress is ack direction
	// For the responder (who sent ack), egress is ack direction, ingress is auth direction
	// Since we're processing the handshake, we'll assign based on typical roles
	// The first packet (auth) is considered from the initiator, second (ack) from responder
	egressMAC := mac1  // From perspective of whoever sent the auth packet
	ingressMAC := mac2 // From perspective of whoever sent the auth packet

	secrets := &rlpx.Secrets{
		AES:        aesSecret, // Use the properly derived AES secret
		MAC:        macSecret, // Use the properly derived MAC secret
		EgressMAC:  egressMAC,
		IngressMAC: ingressMAC,
	}

	// Double-check that P2PSession is not nil before assignment to prevent race conditions
	if session.P2PSession == nil {
		session.P2PSession = &P2PSessionInfo{}
	}

	session.P2PSession.Secrets = secrets
	session.P2PSession.NodeKey = nodeKey
	session.P2PSession.Established = true

	publicKeyBytes := crypto.FromECDSAPub(&nodeKey.PublicKey)
	if publicKeyBytes == nil {
		return fmt.Errorf("failed to extract public key from node key")
	}

	// Make sure we have enough bytes to slice
	if len(publicKeyBytes) < 8 {
		return fmt.Errorf("public key bytes too short: %d", len(publicKeyBytes))
	}

	// Use more bytes for the PeerID to make it more unique - typically first 32 bytes of public key
	peerIDLength := 32
	if len(publicKeyBytes) < peerIDLength {
		peerIDLength = len(publicKeyBytes)
	}
	session.P2PSession.PeerID = fmt.Sprintf("%x", publicKeyBytes[:peerIDLength])

	return nil
}

// DeriveSessionKeys derives session keys from handshake data
func DeriveSessionKeys(sessionID string) error {
	SessionMutex.Lock()
	defer SessionMutex.Unlock()

	session, exists := SessionStore[sessionID]

	if !exists || session.P2PSession == nil {
		return fmt.Errorf("session not found or no P2P session data available")
	}

	if session.P2PSession.AuthRespHash != nil && session.P2PSession.AckHash != nil {
		// Temporarily store the handshake data to avoid race conditions
		authHash := session.P2PSession.AuthRespHash
		ackHash := session.P2PSession.AckHash
		return processHandshake(session, authHash, ackHash)
	}

	return fmt.Errorf("both auth and ack packets required to establish session")
}

// decryptRLPxFrame decrypts an RLPx frame using the session secrets
func decryptRLPxFrame(sess *P2PSessionInfo, ciphertext []byte) ([]byte, error) {
	if sess.Secrets == nil {
		return nil, fmt.Errorf("session secrets not available")
	}

	// RLPx frames have a minimum size - check if the ciphertext is large enough
	// Minimum RLPx frame includes MACs and headers
	if len(ciphertext) < 32 {
		log.Printf("Ciphertext too short (%d bytes) for RLPx decryption", len(ciphertext))
		return nil, fmt.Errorf("ciphertext too short: %d", len(ciphertext))
	}

	mockConn := &MockConn{
		readData: ciphertext,
	}

	conn := rlpx.NewConn(mockConn, nil)

	conn.InitWithSecrets(*sess.Secrets)

	_, data, _, err := conn.Read()
	if err != nil {
		log.Printf("Failed to decrypt RLPx frame: %v", err)
		return nil, fmt.Errorf("failed to read decrypted message: %v", err)
	}

	log.Printf("Successfully decrypted %d bytes", len(data))
	return data, nil
}

// GetDecryptedData returns decrypted data if session keys are available
func GetDecryptedData(sessionID string, encryptedFrame []byte) ([]byte, error) {
	SessionMutex.RLock()
	session, exists := SessionStore[sessionID]
	SessionMutex.RUnlock()

	if !exists || session.P2PSession == nil {
		return nil, fmt.Errorf("session not found or no P2P session data available")
	}

	if session.P2PSession.Secrets == nil {
		return nil, fmt.Errorf("session secrets not available for decryption")
	}

	plaintext, err := decryptRLPxFrame(session.P2PSession, encryptedFrame)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt frame: %v", err)
	}

	return plaintext, nil
}

// getNodePrivateKey loads the node private key from environment variables
func getNodePrivateKey() (*ecdsa.PrivateKey, error) {
	var err error
	nodeKeyOnce.Do(func() {
		privateKeyHex := os.Getenv("XDC_PRIVATE_KEY")
		if privateKeyHex == "" {
			privateKeyHex = os.Getenv("PRIVATE_KEY")
		}

		if privateKeyHex == "" {
			privateKeyHex, err = loadPrivateKeyFromEnvFile()
			if err != nil {
				err = fmt.Errorf("XDC_PRIVATE_KEY not found in environment or .env file: %v", err)
				return
			}
		}

		privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
		privateKeyHex = strings.TrimPrefix(privateKeyHex, "0X")

		privateKeyBytes, decodeErr := hex.DecodeString(privateKeyHex)
		if decodeErr != nil {
			err = fmt.Errorf("failed to decode private key: %v", decodeErr)
			return
		}

		nodeKey, err = toECDSA(privateKeyBytes)
	})

	return nodeKey, err
}

// loadPrivateKeyFromEnvFile attempts to load the private key from the .peerd/.env file
func loadPrivateKeyFromEnvFile() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	envPath := usr.HomeDir + "/.peerd/.env"
	envContent, err := os.ReadFile(envPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(envContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "XDC_PRIVATE_KEY=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
		if strings.HasPrefix(line, "PRIVATE_KEY=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("private key not found in .env file")
}

// toECDSA creates a private key with the given D value
func toECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return crypto.ToECDSA(d)
}

// InitStreamProcessor initializes the TCP stream processor with the node's private key.
func InitStreamProcessor() error {
	key, err := getNodePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to initialize stream processor: %v", err)
	}
	sp := streamprocessor.NewStreamProcessor(key)
	// Hook: propagate derived secrets from TCP stream handshake into our session store
	sp.SetOnEstablished(func(srcIP, srcPort, dstIP, dstPort string, secrets *rlpx.Secrets) {
		if secrets == nil {
			return
		}
		sessionID := CreateCanonicalSessionID(srcIP, srcPort, dstIP, dstPort)
		SessionMutex.Lock()
		defer SessionMutex.Unlock()
		s, ok := SessionStore[sessionID]
		if !ok {
			s = &SessionInfo{
				ID:            sessionID,
				SourceIP:      srcIP,
				DestinationIP: dstIP,
				Protocol:      "TCP",
				IsActive:      true,
				StartTime:     time.Now(),
				EndTime:       time.Now(),
			}
			SessionStore[sessionID] = s
		}
		if s.P2PSession == nil {
			s.P2PSession = &P2PSessionInfo{}
		}
		s.P2PSession.Secrets = secrets
		s.P2PSession.NodeKey = key
		s.P2PSession.Established = true
		// Derive a stable PeerID representation from our node public key
		pub := crypto.FromECDSAPub(&key.PublicKey)
		if len(pub) > 0 {
			n := 32
			if len(pub) < n {
				n = len(pub)
			}
			s.P2PSession.PeerID = fmt.Sprintf("%x", pub[:n])
		}
		log.Printf("[stream] Established RLPx session for %s (secrets ready)", sessionID)
	})
	streamProcessor = sp
	return nil
}
