package logger

import (
	"encoding/json"
	"fmt"
	"log"
)

// Logger wraps logging functionality for XDC and non-XDC traffic
type Logger struct {
	outputFormat string
}

// NewLogger creates a new logger instance
func NewLogger(outputFormat string) *Logger {
	return &Logger{
		outputFormat: outputFormat,
	}
}

// LogXDCPacket logs XDC traffic packets
func (l *Logger) LogXDCPacket(packetInfo map[string]interface{}) {
	if packetInfo["is_xdc"] == nil {
		return // Not an XDC packet
	}

	isXDC, ok := packetInfo["is_xdc"].(bool)
	if !ok || !isXDC {
		return // Not an XDC packet
	}

	l.logPacket(packetInfo)
}

// LogNonXDCPacket logs non-XDC traffic packets
func (l *Logger) LogNonXDCPacket(packetInfo map[string]interface{}) {
	if packetInfo["is_xdc"] == nil {
		// If is_xdc field doesn't exist, treat as non-XDC
		l.logPacket(packetInfo)
		return
	}

	isXDC, ok := packetInfo["is_xdc"].(bool)
	if !ok || !isXDC {
		// It's a non-XDC packet
		l.logPacket(packetInfo)
	}
}

// LogAnyPacket logs any packet regardless of XDC status
func (l *Logger) LogAnyPacket(packetInfo map[string]interface{}) {
	l.logPacket(packetInfo)
}

// logPacket handles the actual logging based on output format
func (l *Logger) logPacket(packetInfo map[string]interface{}) {
	switch l.outputFormat {
	case "text":
		l.logText(packetInfo)
	case "csv":
		l.logCSV(packetInfo)
	default: // json
		l.logJSON(packetInfo)
	}
}

// logText logs packet in text format
func (l *Logger) logText(packetInfo map[string]interface{}) {
	fmt.Printf("[%s] %s:%s -> %s:%s (%s) | Type: %s | Size: %d bytes\n",
		packetInfo["timestamp"],
		packetInfo["src_ip"], packetInfo["src_port"],
		packetInfo["dst_ip"], packetInfo["dst_port"],
		packetInfo["protocol"],
		packetInfo["type"],
		packetInfo["size"])

	// Print decrypted message if available
	if decryptedMsg, ok := packetInfo["decrypted_msg"].(string); ok && decryptedMsg != "" {
		fmt.Printf("Decrypted msg: %s\n", decryptedMsg)
	}
}

// logCSV logs packet in CSV format
func (l *Logger) logCSV(packetInfo map[string]interface{}) {
	decryptedMsg := ""
	if dm, ok := packetInfo["decrypted_msg"].(string); ok {
		decryptedMsg = dm
	}
	fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%d,\"%s\"\n",
		packetInfo["timestamp"],
		packetInfo["src_ip"], packetInfo["src_port"],
		packetInfo["dst_ip"], packetInfo["dst_port"],
		packetInfo["protocol"],
		packetInfo["type"],
		packetInfo["details"],
		packetInfo["size"],
		decryptedMsg)
}

// logJSON logs packet in JSON format
func (l *Logger) logJSON(packetInfo map[string]interface{}) {
	jsonData, err := json.Marshal(packetInfo)
	if err != nil {
		log.Printf("Error marshaling packet info: %v", err)
		return
	}
	fmt.Println(string(jsonData))

	// Print decrypted message separately if available (for readability)
	if decryptedMsg, ok := packetInfo["decrypted_msg"].(string); ok && decryptedMsg != "" {
		fmt.Printf("Decrypted msg: %s\n", decryptedMsg)
	}
}
