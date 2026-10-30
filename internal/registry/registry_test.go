package registry

import (
	"net/netip"
	"testing"
)

func peer(url string) Peer {
	return Peer{
		ID:   url,
		URL:  url,
		Addr: netip.MustParseAddr("192.168.178.10"),
	}
}

func TestMarkReportsNewPeers(t *testing.T) {
	registry := New()

	if !registry.Mark(peer("http://192.168.178.10:5055")) {
		t.Fatal("expected the first mark to report a new peer")
	}

	if registry.Mark(peer("http://192.168.178.10:5055")) {
		t.Fatal("expected the second mark to report an existing peer")
	}
}

func TestEndScanRemovesPeersAfterFiveMisses(t *testing.T) {
	registry := New()
	url := "http://192.168.178.10:5055"

	registry.Mark(peer(url))

	for scan := 1; scan <= 4; scan++ {
		registry.BeginScan()

		if removed := registry.EndScan(); len(removed) != 0 {
			t.Fatalf("scan %d removed %d peers, expected 0", scan, len(removed))
		}
	}

	registry.BeginScan()

	removed := registry.EndScan()

	if len(removed) != 1 || removed[0].URL != url {
		t.Fatalf("expected the peer to be removed on the fifth miss, got %#v", removed)
	}

	if len(registry.Snapshot()) != 0 {
		t.Fatal("expected the registry to be empty")
	}
}

func TestMarkResetsMisses(t *testing.T) {
	registry := New()
	url := "http://192.168.178.10:5055"

	registry.Mark(peer(url))
	registry.BeginScan()
	registry.BeginScan()
	registry.Mark(peer(url))
	registry.BeginScan()

	if removed := registry.EndScan(); len(removed) != 0 {
		t.Fatalf("expected the peer to survive, got %#v", removed)
	}
}
