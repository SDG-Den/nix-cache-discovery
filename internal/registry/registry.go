package registry

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

type Peer struct {
	ID       string
	URL      string
	Addr     netip.Addr
	LastSeen time.Time
}

type Registry struct {
	mu    sync.RWMutex
	peers map[string]Peer
	ttl   time.Duration
}

func New(ttl time.Duration) *Registry {
	return &Registry{
		peers: make(map[string]Peer),
		ttl:   ttl,
	}
}

func (registry *Registry) Mark(peer Peer) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	registry.peers[peer.URL] = peer
}

func (registry *Registry) Clear() {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	registry.peers = make(map[string]Peer)
}

func (registry *Registry) Snapshot() []Peer {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	cutoff := time.Now().Add(-registry.ttl)
	peers := make([]Peer, 0, len(registry.peers))

	for url, peer := range registry.peers {
		if peer.LastSeen.Before(cutoff) {
			delete(registry.peers, url)
			continue
		}

		peers = append(peers, peer)
	}

	sort.Slice(peers, func(left, right int) bool {
		return peers[left].URL < peers[right].URL
	})

	return peers
}
