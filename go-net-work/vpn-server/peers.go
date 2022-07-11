package main

import (
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// TODO: this can later be replaced with PubKey or with some combination of PubKey + IP
type PeerID netip.Addr

func (pid PeerID) String() string {
	return netip.Addr(pid).String()
}

type Peer struct {
	ID   PeerID
	Addr string
	// TODO: public keys etc
}

type PeerStatus int

const (
	Unknown PeerStatus = iota
	Down
	Up
)

type PeerState struct {
	Status        PeerStatus
	LastHeartbeat *time.Time
}

func (p *Peer) name() {

}

// TODO: test it somehow?
type PeerStore struct {
	sync.RWMutex

	// TODO: should this be one map with all those things captured in the struct?
	PeerInfo    map[PeerID]Peer
	PeerState   map[PeerID]PeerState
	Connections map[PeerID]chan<- []byte
}

func InitializePeers(bindIP string, peers []Peer, logger zerolog.Logger) (*PeerStore, error) {
	ps := PeerStore{
		RWMutex:     sync.RWMutex{},
		PeerInfo:    make(map[PeerID]Peer, len(peers)),
		PeerState:   make(map[PeerID]PeerState, len(peers)),
		Connections: make(map[PeerID]chan<- []byte, len(peers)),
	}

	logger = logger.With().Str("module", "peer-store").Logger()

	for _, peer := range peers {
		ps.PeerInfo[peer.ID] = peer
		ps.PeerState[peer.ID] = PeerState{
			Status:        Unknown,
			LastHeartbeat: nil,
		}
		c := make(chan []byte, 100) // TODO: what would be the correct buffer?
		ps.Connections[peer.ID] = c

		// TODO: should I fail here? I suppose because this means wrong address?
		// TODO: this is no explicit enough - I prefer 2 functions and make it transparent
		err := ps.connectToPeer(bindIP, peer, c, logger.With().Str("peer", peer.ID.String()).Logger())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to connect to peer %q", peer.ID)
		}
	}

	return &ps, nil
}

// TODO: split to 2 functions so that the actual goroutine func does not return error
func (p *PeerStore) connectToPeer(localBindAddr string, peer Peer, c <-chan []byte, logger zerolog.Logger) error {
	logger.Debug().Msg("Setting up peer addresses...")

	peerAddr, err := net.ResolveUDPAddr("udp", peer.Addr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve peer address")
	}
	// TODO: how to pick a random port? Will that work?
	localAddr, err := net.ResolveUDPAddr("udp", localBindAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve peer address")
	}

	logger = logger.With().
		Str("peer-addr", peerAddr.String()).
		Str("local-addr", localAddr.String()).
		Logger()

	logger.Info().Msg("Initializing peer connection...")
	go p.peerConnection(localAddr, peerAddr, c, logger)

	return nil
}

// TODO: this should update the status, do the hearhbeats etc
func (p *PeerStore) peerConnection(localAddr, peerAddr *net.UDPAddr, c <-chan []byte, logger zerolog.Logger) {
	for {
		udpConn, err := net.DialUDP("udp", localAddr, peerAddr)
		if err != nil {
			logger.Err(err).Msg("Failed to connect to peer via UDP")
			time.Sleep(5 * time.Second) // TODO: some configurable, exponential backoff
			continue
		}
		log.Info().Msg("Successfully connected to the peer...")

		for {
			packet := <-c

			// TODO: perhaps some additional debug info about the packet

			log.Info().Msg("Received packet for peer, sending through UDP connection...")

			_, err = udpConn.Write(packet)
			if err != nil {
				// TODO: differentiate error here, whether we should dial again or just log?
				log.Err(err).Msg("error while writing UDP to endpoint")
				continue // TODO: this will just continue inner loop
			}
		}
	}
}

func (p *PeerStore) ForwardToPeer(packet []byte, peerID PeerID) error {
	cn, found := p.Connection(peerID)
	if !found {
		return errors.Errorf("peer with ID %q not found", peerID.String())
	}

	select {
	case cn <- packet:
	default:
		return errors.Errorf("peer %s queue is full, dropping packet", peerID.String())
	}
	return nil
}

func (p *PeerStore) ReloadPeers() {
	// TODO
}

func (p *PeerStore) Connection(id PeerID) (chan<- []byte, bool) {
	p.RWMutex.RLock()
	defer p.RWMutex.RUnlock()

	c, found := p.Connections[id]
	if !found {
		return nil, false
	}

	return c, true
}
