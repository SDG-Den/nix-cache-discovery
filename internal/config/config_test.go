package config

import (
	"net/netip"
	"testing"
	"time"
)

func TestParsePrefixes(t *testing.T) {
	prefixes, err := ParsePrefixes([]string{"192.168.1.7/24", "fd00::/64"})

	if err != nil {
		t.Fatal(err)
	}

	if len(prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(prefixes))
	}

	if prefixes[0].String() != "192.168.1.0/24" {
		t.Fatalf("prefix was not masked: %s", prefixes[0])
	}
}

func TestValidateRejectsRangeOutsideAllowedClients(t *testing.T) {
	cfg := Config{
		Port:              5000,
		DiscoveryRanges:   mustPrefixes(t, "192.168.1.0/24"),
		AllowedClients:    mustPrefixes(t, "10.0.0.0/8"),
		DiscoveryInterval: time.Minute,
		DiscoveryTimeout:  time.Second,
		DiscoveryWorkers:  4,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateAcceptsContainedRange(t *testing.T) {
	cfg := Config{
		Port:              5000,
		DiscoveryRanges:   mustPrefixes(t, "192.168.1.0/24"),
		AllowedClients:    mustPrefixes(t, "192.168.0.0/16"),
		DiscoveryInterval: time.Minute,
		DiscoveryTimeout:  time.Second,
		DiscoveryWorkers:  4,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()

	prefixes, err := ParsePrefixes(values)

	if err != nil {
		t.Fatal(err)
	}

	return prefixes
}
