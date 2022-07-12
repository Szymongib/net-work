package main

import (
	"github.com/rs/zerolog"
	tun_tap "github.com/szymongib/net-work/go-net-work/pkg/tun-tap"
	"golang.org/x/net/ipv4"
)

// TODO: so would one goroutine per peer be enough? Or is it possible to parallelize it further?
// Is one goroutine reading from the interface enough? Could it be somehow improved?
// TODO: try to really benchmark it to learn some benchmarking skills

func forwardPackets(peerStore *PeerStore, iface *tun_tap.TunVInterface, logger zerolog.Logger) {
	buffer := make([]byte, 2048) // TODO: have no idea how big the buffer should be
	logger = logger.With().Str("module", "tun-reader").Logger()
	//	Str("local-addr", localAddr.String()).Logger()
	//logger.Info().Msg("Reading tun and forwarding...")

	for {
		read, err := iface.RWC.Read(buffer)
		if err != nil {
			logger.Err(err).Msg("error while reading from virtual interface")
			continue
		}
		packet := buffer[:read]

		//flog := extendLogWithPacketDetails(buffer[:read], logger)
		ipHeader, err := ipv4.ParseHeader(packet)
		if err != nil {
			logger.Err(err).Msg("failed to parse IP header, dropping packet")
			continue
		}

		//addr, ok := netip.AddrFromSlice(ipHeader.Dst)
		//if !ok {
		//	logger.Error().Msg("failed to parse IP address, dropping packet")
		//	continue
		//}

		// TODO: here I need to read shit from network interface, parse IP
		// header and decide where to send it.

		peerID := PeerID(ipHeader.Dst.To4().String())
		flog := logger.With().Str("peer", peerID.String()).Logger()

		flog.Debug().Str("peer", peerID.String()).Msg("Received packet for peer, forwarding...")

		err = peerStore.ForwardToPeer(packet, peerID)
		if err != nil {
			flog.Err(err).Msg("failed to forward packet to peer")
			continue
		}
	}
}
