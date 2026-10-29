package server

import (
	"net/netip"
	"testing"
)

func TestValidHashPart(t *testing.T) {
	cases := map[string]bool{
		"9l0j15jg8634hkb6d4c9y95mpxl0nhrd": true,
		"00000000000000000000000000000000": true,
		"9l0j15jg8634hkb6d4c9y95mpxl0nhre": false,
	}

	for hashPart, expected := range cases {
		if actual := validHashPart(hashPart); actual != expected {
			t.Errorf("validHashPart(%q) = %v, want %v", hashPart, actual, expected)
		}
	}
}

func TestValidNarPath(t *testing.T) {
	cases := map[string]bool{
		"/nar/9l0j15jg8634hkb6d4c9y95mpxl0nhrd-1y1zn2h9pza8ha96l3xrvqananbqxcgw8iirgxixmmzwd8brlhrf.nar": true,
		"/nar/0b56hsfzp1d4kx9j095zk64b0zmi189s3ih8mk2zyshpi48fgw76.nar.zst":                              true,
		"/nar/abc.nar.xz":    true,
		"/nar/../etc/passwd": false,
		"/nar/abc.nar":       true,
		"/nar/abc.txt":       false,
		"/nar/a/b.nar":       false,
		"/nar/ABC.nar":       false,
		"/other/abc.nar":     false,
	}

	for path, expected := range cases {
		if actual := validNarPath(path); actual != expected {
			t.Errorf("validNarPath(%q) = %v, want %v", path, actual, expected)
		}
	}
}

func TestAllowed(t *testing.T) {
	server := &Server{options: Options{
		Allowlist: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("fd00::/64"),
		},
	}}

	cases := map[string]bool{
		"127.0.0.1":   true,
		"::1":         true,
		"192.168.1.5": true,
		"192.168.2.5": false,
		"10.0.0.1":    false,
		"fd00::1":     true,
		"fd01::1":     false,
	}

	for address, expected := range cases {
		if actual := server.allowed(netip.MustParseAddr(address)); actual != expected {
			t.Errorf("allowed(%s) = %v, want %v", address, actual, expected)
		}
	}
}
