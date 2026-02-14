package proxy

import (
	"testing"
)

func TestMsgName(t *testing.T) {
	tests := []struct {
		code uint64
		want string
	}{
		{HandshakeMsg, "Hello"},
		{DiscMsg, "Disconnect"},
		{PingMsg, "Ping"},
		{PongMsg, "Pong"},
		{StatusMsg, "Status"},
		{NewBlockMsg, "NewBlock"},
		{TxMsg, "Txns"},
		{XDPoSVoteMsg, "XDPoS/Vote"},
		{XDPoSTimeoutMsg, "XDPoS/Timeout"},
		{0xFF, "0xff"}, // unknown
	}

	for _, tt := range tests {
		got := MsgName(tt.code)
		if got != tt.want {
			t.Errorf("MsgName(0x%02x) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestIsProtocolMsg(t *testing.T) {
	if IsProtocolMsg(PingMsg) {
		t.Error("Ping should not be a protocol msg")
	}
	if IsProtocolMsg(PongMsg) {
		t.Error("Pong should not be a protocol msg")
	}
	if !IsProtocolMsg(StatusMsg) {
		t.Error("Status should be a protocol msg")
	}
	if !IsProtocolMsg(NewBlockMsg) {
		t.Error("NewBlock should be a protocol msg")
	}
	if !IsProtocolMsg(XDPoSVoteMsg) {
		t.Error("XDPoS/Vote should be a protocol msg")
	}
}
