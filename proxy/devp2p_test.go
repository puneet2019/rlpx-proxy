package proxy

import (
	"testing"
)

func TestNegotiateEthVersion(t *testing.T) {
	tests := []struct {
		name     string
		caps     []Cap
		expected uint32
	}{
		{
			name:     "XDC peer (eth/62, eth/63, eth/100)",
			caps:     []Cap{{Name: "eth", Version: 62}, {Name: "eth", Version: 63}, {Name: "eth", Version: 100}},
			expected: 100,
		},
		{
			name:     "modern Ethereum peer (eth/67, eth/68)",
			caps:     []Cap{{Name: "eth", Version: 67}, {Name: "eth", Version: 68}},
			expected: 68,
		},
		{
			name:     "old peer (eth/63 only)",
			caps:     []Cap{{Name: "eth", Version: 63}},
			expected: 63,
		},
		{
			name:     "no eth caps",
			caps:     []Cap{{Name: "snap", Version: 1}},
			expected: 63, // fallback
		},
		{
			name:     "empty caps",
			caps:     nil,
			expected: 63, // fallback
		},
		{
			name:     "unknown version only",
			caps:     []Cap{{Name: "eth", Version: 999}},
			expected: 63, // fallback — not in our set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := negotiateEthVersion(tt.caps)
			if got != tt.expected {
				t.Errorf("negotiateEthVersion(%v) = %d, want %d", tt.caps, got, tt.expected)
			}
		})
	}
}

func TestHelloRoundTrip(t *testing.T) {
	original := &Hello{
		Version:    5,
		Name:       "test-node/1.0",
		Caps:       []Cap{{Name: "eth", Version: 100}, {Name: "eth", Version: 63}},
		ListenPort: 30303,
		ID:         make([]byte, 64),
	}

	data, err := encodeHello(original)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}

	decoded, err := decodeHello(data)
	if err != nil {
		t.Fatalf("decodeHello: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version = %d, want %d", decoded.Version, original.Version)
	}
	if decoded.Name != original.Name {
		t.Errorf("name = %q, want %q", decoded.Name, original.Name)
	}
	if len(decoded.Caps) != len(original.Caps) {
		t.Fatalf("caps len = %d, want %d", len(decoded.Caps), len(original.Caps))
	}
	for i, c := range decoded.Caps {
		if c.Name != original.Caps[i].Name || c.Version != original.Caps[i].Version {
			t.Errorf("cap[%d] = %v, want %v", i, c, original.Caps[i])
		}
	}
}

func TestAllCapsContainsXDC(t *testing.T) {
	caps := allCaps()
	found := false
	for _, c := range caps {
		if c.Name == "eth" && c.Version == 100 {
			found = true
			break
		}
	}
	if !found {
		t.Error("allCaps() should include eth/100 (XDC)")
	}
}
