package registry

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const maxMisses = 3

type Peer struct {
	ID       string
	URL      string
	Addr     netip.Addr
	LastSeen time.Time
	Misses   int
}

type Registry struct {
	mu    sync.RWMutex
	peers map[string]Peer
}

func New() *Registry {
	return &Registry{
		peers: make(map[string]Peer),
	}
}

func (registry *Registry) BeginScan() {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	for url, peer := range registry.peers {
		peer.Misses++
		registry.peers[url] = peer
	}
}

func (registry *Registry) Mark(peer Peer) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	_, existed := registry.peers[peer.URL]

	peer.Misses = 0
	peer.LastSeen = time.Now()
	registry.peers[peer.URL] = peer

	return !existed
}

func (registry *Registry) EndScan() []Peer {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	var removed []Peer

	for url, peer := range registry.peers {
		if peer.Misses >= maxMisses {
			removed = append(removed, peer)
			delete(registry.peers, url)
		}
	}

	sort.Slice(removed, func(left, right int) bool {
		return removed[left].URL < removed[right].URL
	})

	return removed
}

func (registry *Registry) Clear() {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	registry.peers = make(map[string]Peer)
}

func (registry *Registry) Snapshot() []Peer {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	peers := make([]Peer, 0, len(registry.peers))

	for _, peer := range registry.peers {
		peers = append(peers, peer)
	}

	sort.Slice(peers, func(left, right int) bool {
		return peers[left].URL < peers[right].URL
	})

	return peers
}
