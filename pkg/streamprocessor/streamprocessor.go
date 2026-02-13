package streamprocessor

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type StreamProcessor struct {
	assembler     *tcpassembly.Assembler
	streams       map[string]*RLPXSession
	mutex         sync.RWMutex
	privateKey    *ecdsa.PrivateKey
	onEstablished SessionEstablishedCallback
}

type streamFactory struct {
	processor *StreamProcessor
}

type SessionEstablishedCallback func(srcIP, srcPort, dstIP, dstPort string, secrets *rlpx.Secrets)

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	s := &RLPXStream{
		net:       netFlow,
		tcp:       tcpFlow,
		r:         &r,
		processor: f.processor,
	}
	go s.run()
	return &r
}

type RLPXStream struct {
	net       gopacket.Flow
	tcp       gopacket.Flow
	r         *tcpreader.ReaderStream
	processor *StreamProcessor
}

type RLPXSession struct {
	mu sync.Mutex

	stage int

	authPacket []byte
	ackPacket  []byte

	conn      *rlpx.Conn
	secrets   *rlpx.Secrets
	processor *StreamProcessor

	srcIP   string
	dstIP   string
	srcPort string
	dstPort string
}

const (
	stageAuth = iota
	stageAck
	stageFrames
)

const (
	minAuthSize = 194 // minimum size for pre-EIP-8 auth; EIP-8 may be larger
	minAckSize  = 97  // minimum size for pre-EIP-8 ack; EIP-8 may be larger
)

func NewStreamProcessor(privateKey *ecdsa.PrivateKey) *StreamProcessor {
	sp := &StreamProcessor{
		streams:    make(map[string]*RLPXSession),
		privateKey: privateKey,
	}
	streamPool := tcpassembly.NewStreamPool(&streamFactory{processor: sp})
	sp.assembler = tcpassembly.NewAssembler(streamPool)
	return sp
}

// SetOnEstablished sets a callback invoked when a session handshake is completed
func (sp *StreamProcessor) SetOnEstablished(cb SessionEstablishedCallback) {
	sp.onEstablished = cb
}

// canonicalKey builds a direction-agnostic key from endpoints
func canonicalKey(srcIP, srcPort, dstIP, dstPort string) string {
	a := srcIP + ":" + srcPort
	b := dstIP + ":" + dstPort
	if a < b {
		return a + "-" + b
	}
	return b + "-" + a
}

func (sp *StreamProcessor) Process(packet gopacket.Packet) {
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		sp.assembler.AssembleWithTimestamp(
			packet.TransportLayer().TransportFlow(),
			tcp,
			packet.Metadata().Timestamp,
		)
	}
}

func (s *RLPXStream) run() {
	defer s.r.Close()

	srcIP := s.net.Src().String()
	dstIP := s.net.Dst().String()
	srcPort := s.tcp.Src().String()
	dstPort := s.tcp.Dst().String()
	key := canonicalKey(srcIP, srcPort, dstIP, dstPort)

	session := s.processor.getOrCreateSession(key, srcIP, srcPort, dstIP, dstPort)

	buf := make([]byte, 4096)
	for {
		n, err := s.r.Read(buf)
		if err != nil {
			return
		}
		session.Process(buf[:n])
	}
}

func (sp *StreamProcessor) getOrCreateSession(connKey, srcIP, srcPort, dstIP, dstPort string) *RLPXSession {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	session, exists := sp.streams[connKey]
	if !exists {
		session = &RLPXSession{
			stage:     stageAuth,
			processor: sp,
			srcIP:     srcIP,
			dstIP:     dstIP,
			srcPort:   srcPort,
			dstPort:   dstPort,
		}
		sp.streams[connKey] = session
	} else {
		// Backfill endpoints if they are empty (first-time info)
		if session.srcIP == "" {
			session.srcIP = srcIP
		}
		if session.dstIP == "" {
			session.dstIP = dstIP
		}
		if session.srcPort == "" {
			session.srcPort = srcPort
		}
		if session.dstPort == "" {
			session.dstPort = dstPort
		}
	}

	return session
}

func (s *RLPXSession) Process(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.stage {
	case stageAuth:
		s.authPacket = append(s.authPacket, data...)
		// Use a minimum threshold to advance; EIP-8 packets may be larger
		if len(s.authPacket) >= minAuthSize {
			s.stage = stageAck
		}

	case stageAck:
		s.ackPacket = append(s.ackPacket, data...)
		// Use a minimum threshold to attempt initialization
		if len(s.ackPacket) >= minAckSize {
			if err := s.initRLPx(); err != nil {
				fmt.Printf("Handshake error for session: %v\n", err)
			} else {
				s.stage = stageFrames
			}
		}

	case stageFrames:
		// Process encrypted frames
		// This would handle decryption of subsequent RLPx frames
	}
}

// BufferedConn wraps the handshake packets for RLPx connection
type BufferedConn struct {
	authData []byte
	ackData  []byte
	pos      int
	isAuth   bool
}

func NewBufferedConn(authData, ackData []byte, startWithAuth bool) *BufferedConn {
	return &BufferedConn{
		authData: authData,
		ackData:  ackData,
		isAuth:   startWithAuth, // true: serve auth first; false: serve ack first
	}
}

func (bc *BufferedConn) Read(b []byte) (n int, err error) {
	if bc.isAuth && bc.pos < len(bc.authData) {
		n = copy(b, bc.authData[bc.pos:])
		bc.pos += n
		if bc.pos >= len(bc.authData) {
			bc.isAuth = false
			bc.pos = 0
		}
	} else if !bc.isAuth && bc.pos < len(bc.ackData) {
		n = copy(b, bc.ackData[bc.pos:])
		bc.pos += n
	} else {
		// No more data to read - this simulates the handshake completion
		return 0, fmt.Errorf("handshake data exhausted")
	}
	return n, nil
}

func (bc *BufferedConn) Write(b []byte) (n int, err error) {
	// For handshake simulation, writes are typically responses
	return len(b), nil
}

func (bc *BufferedConn) Close() error                       { return nil }
func (bc *BufferedConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (bc *BufferedConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (bc *BufferedConn) SetDeadline(t time.Time) error      { return nil }
func (bc *BufferedConn) SetReadDeadline(t time.Time) error  { return nil }
func (bc *BufferedConn) SetWriteDeadline(t time.Time) error { return nil }

func (s *RLPXSession) initRLPx() error {
	if len(s.authPacket) == 0 || len(s.ackPacket) == 0 {
		return fmt.Errorf("missing auth or ack packet for handshake")
	}

	// Try both directions: start with auth first (responder case), then ack first (initiator case)
	tryHandshake := func(startWithAuth bool) error {
		wrappedConn := NewBufferedConn(s.authPacket, s.ackPacket, startWithAuth)
		conn := rlpx.NewConn(wrappedConn, nil)

		// Attempt signature: Handshake(priv *ecdsa.PrivateKey) (*rlpx.Secrets, error)
		if hs, ok := any(conn).(interface {
			Handshake(*ecdsa.PrivateKey) (*rlpx.Secrets, error)
		}); ok {
			se, err2 := hs.Handshake(s.processor.privateKey)
			if err2 != nil {
				return err2
			}
			s.conn = conn
			s.secrets = se
			if s.processor.onEstablished != nil {
				s.processor.onEstablished(s.srcIP, s.srcPort, s.dstIP, s.dstPort, s.secrets)
			}
			return nil
		}
		// Attempt signature: Handshake(priv *ecdsa.PrivateKey) (rlpx.Secrets, error)
		if hs, ok := any(conn).(interface {
			Handshake(*ecdsa.PrivateKey) (rlpx.Secrets, error)
		}); ok {
			se, err2 := hs.Handshake(s.processor.privateKey)
			if err2 != nil {
				return err2
			}
			s.conn = conn
			secrets := se
			s.secrets = &secrets
			if s.processor.onEstablished != nil {
				s.processor.onEstablished(s.srcIP, s.srcPort, s.dstIP, s.dstPort, s.secrets)
			}
			return nil
		}
		return fmt.Errorf("rlpx.Conn does not expose a compatible Handshake method in this go-ethereum version")
	}

	// First try assuming remote sent auth first (we are responder)
	if err := tryHandshake(true); err == nil {
		return nil
	}
	// Retry assuming we sent auth first (we are initiator)
	if err := tryHandshake(false); err == nil {
		return nil
	}

	return fmt.Errorf("rlpx handshake failed for both directions on %s:%s-%s:%s", s.srcIP, s.srcPort, s.dstIP, s.dstPort)
}

// GetSecrets returns the derived secrets for this session
func (s *RLPXSession) GetSecrets() *rlpx.Secrets {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets
}

// GetConn returns the RLPx connection for this session
func (s *RLPXSession) GetConn() *rlpx.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// IsEstablished returns true if the handshake is complete
func (s *RLPXSession) IsEstablished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets != nil
}
