package discovery

import (
	"net/netip"
	"testing"

	"github.com/den/nix-cache-discovery/internal/registry"
)

func TestBuildTargetsPrioritizesKnownPeersAndLocalSubnets(t *testing.T) {
	ranges := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	locals := []netip.Prefix{netip.MustParsePrefix("192.168.178.0/24")}
	peerAddress := netip.MustParseAddr("192.168.178.50")

	targets := buildTargets(ranges, locals, []registry.Peer{{Addr: peerAddress}})

	if len(targets) != 65536 {
		t.Fatalf("expected 65536 unique targets, got %d", len(targets))
	}

	if targets[0] != peerAddress {
		t.Fatalf("expected the known peer first, got %s", targets[0])
	}

	if targets[1] != netip.MustParseAddr("192.168.178.0") {
		t.Fatalf("expected the local subnet second, got %s", targets[1])
	}

	localIndex := indexOf(targets, netip.MustParseAddr("192.168.178.200"))
	remoteIndex := indexOf(targets, netip.MustParseAddr("192.168.0.5"))

	if localIndex < 0 || remoteIndex < 0 {
		t.Fatal("expected both addresses in the target list")
	}

	if localIndex > remoteIndex {
		t.Fatal("local subnet addresses must be probed before the rest of the range")
	}
}

func TestBuildTargetsDeduplicatesOverlappingRanges(t *testing.T) {
	ranges := []netip.Prefix{
		netip.MustParsePrefix("192.168.178.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	targets := buildTargets(ranges, nil, nil)

	if len(targets) != 65536 {
		t.Fatalf("expected overlapping ranges to be deduplicated, got %d targets", len(targets))
	}
}

func TestBuildTargetsIgnoresPeersOutsideRanges(t *testing.T) {
	ranges := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	peerAddress := netip.MustParseAddr("10.0.0.5")

	targets := buildTargets(ranges, nil, []registry.Peer{{Addr: peerAddress}})

	if len(targets) != 65536 {
		t.Fatalf("expected 65536 targets, got %d", len(targets))
	}

	if targets[0] == peerAddress {
		t.Fatal("peer outside the configured ranges must not be probed")
	}
}

func TestIntersect(t *testing.T) {
	wide := netip.MustParsePrefix("192.168.0.0/16")
	narrow := netip.MustParsePrefix("192.168.178.0/24")
	other := netip.MustParsePrefix("10.0.0.0/8")
	v6 := netip.MustParsePrefix("fd00::/64")

	cases := []struct {
		left   netip.Prefix
		right  netip.Prefix
		want   netip.Prefix
		wantOK bool
	}{
		{wide, narrow, narrow, true},
		{narrow, wide, narrow, true},
		{narrow, other, netip.Prefix{}, false},
		{wide, v6, netip.Prefix{}, false},
	}

	for _, test := range cases {
		got, ok := intersect(test.left, test.right)

		if ok != test.wantOK || (ok && got != test.want) {
			t.Errorf("intersect(%s, %s) = %s, %v; want %s, %v", test.left, test.right, got, ok, test.want, test.wantOK)
		}
	}
}

func indexOf(targets []netip.Addr, wanted netip.Addr) int {
	for index, address := range targets {
		if address == wanted {
			return index
		}
	}

	return -1
}
