package main

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/szymongib/net-work/go-net-work/pkg/ipcfg"
	tun_tap "github.com/szymongib/net-work/go-net-work/pkg/tun-tap"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v2"
	"golang.org/x/net/ipv4"
)

// Adding route in Linux:
// ip route add 192.168.64.7 dev tun667

// TODO: configure this, so that packets reaching the server go further to their destination

// TODO:
// - Client needs to listen on UDP
// - Server needs to send the "response" to the client

func main() {
	app := &cli.App{
		Name:  "vpnish",
		Usage: "VPNish thingy. Kind of...",
		Action: func(*cli.Context) error {
			fmt.Println("boom! I say!")
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "server",
				Aliases: []string{"s"},
				Usage:   "Go. And Serve.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "addr",
						Value: "0.0.0.0:55555",
					},
					&cli.StringFlag{
						Name:  "dial-addr",
						Value: "0.0.0.0:55510",
					},
					&cli.StringFlag{
						Name:  "endpoint-addr",
						Value: "192.168.64.8:55555",
					},
					&cli.StringFlag{
						Name:  "ip",
						Value: "172.16.0.1/24",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := PeerConfigFromFlags(ctx)
					return runServer(cfg)
				},
			},
			{
				Name:    "client",
				Aliases: []string{"c"},
				Usage:   "You really need this?.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "addr",
						Value: "0.0.0.0:55555",
					},
					&cli.StringFlag{
						Name:  "dial-addr",
						Value: "0.0.0.0:55510",
					},
					&cli.StringFlag{
						Name:  "endpoint-addr",
						Value: "192.168.64.5:55555",
					},
					&cli.StringFlag{
						Name:  "ip",
						Value: "172.16.0.2/24",
					},
				},
				Action: func(ctx *cli.Context) error {
					clientCfg := PeerConfigFromFlags(ctx)
					return runClient(clientCfg)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Err(err).Msg("error while running app")
	}
}

type PeerConfig struct {
	EndpointAddr string
	ListenAddr   string
	LocalAddr    string
	IP           string
}

func PeerConfigFromFlags(ctx *cli.Context) PeerConfig {
	return PeerConfig{
		ListenAddr:   ctx.String("addr"),
		EndpointAddr: ctx.String("endpoint-addr"),
		LocalAddr:    ctx.String("dial-addr"),
		IP:           ctx.String("ip"),
	}
}

func runServer(cfg PeerConfig) error {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	logger := zerolog.New(os.Stdout)
	logger.Info().Str("addr", cfg.ListenAddr).Msg("Preparing server...")

	logger.Info().Msg("Creating network interface...")
	iface, err := configureTUNInterface("tun666", cfg.IP, logger)
	if err != nil {
		return errors.Wrap(err, "failed to configure virtual interface")
	}

	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve local UDP address")
	}
	endpointAddr, err := net.ResolveUDPAddr("udp", cfg.EndpointAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve endpoint UDP addr")
	}

	listenAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve listen UDP address")
	}

	udpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return errors.Wrap(err, "failed to startup UDP listener")
	}

	go udpReadAndForward(udpConn, iface, logger)
	go tunReadAndForward(localAddr, endpointAddr, iface, logger)

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
	return nil
}

// udpReadAndForward reads packets from UDP connection and forwards them to the
// virtual network interface.
func udpReadAndForward(udpListener *net.UDPConn, iface *tun_tap.TunVInterface, logger zerolog.Logger) {
	buffer := make([]byte, 2048) // TODO: have no idea how big the buffer should be
	logger = logger.With().Str("module", "udp-listener").Logger()
	logger.Info().Str("addr", udpListener.LocalAddr().String()).
		Msg("Starting to listen...")

	for {
		read, addr, err := udpListener.ReadFromUDP(buffer)
		if err != nil {
			logger.Err(err).Msg("error while reading from UDP")
			continue
		}
		flog := logger.With().Str("peer", addr.String()).Logger()
		flog = extendLogWithPacketDetails(buffer[:read], flog)

		flog.Info().Int("read", read).Msg("received UDP packets")

		flog.Info().Msg("Writing to virtual interface")

		// What you write to the network interface goes out to the routing
		// table. **IT IS NOT READ FROM THIS INTERFACE BY iface.RWC.Read!**.
		_, err = iface.RWC.Write(buffer[:read])
		if err != nil {
			flog.Err(err).Msg("error while writing to virtual interface")
			continue
		}
	}
}

// tunReadAndForward reads incoming packets from virtual interface and forwards
// them to the UDP connection
func tunReadAndForward(localAddr, remoteAddr *net.UDPAddr, iface *tun_tap.TunVInterface, logger zerolog.Logger) {
	buffer := make([]byte, 2048) // TODO: have no idea how big the buffer should be
	logger = logger.With().Str("module", "tun-reader").Str("remote-addr", remoteAddr.String()).
		Str("local-addr", localAddr.String()).Logger()
	logger.Info().Msg("Reading tun and forwarding...")

	for {
		udpConn, err := net.DialUDP("udp", localAddr, remoteAddr)
		if err != nil {
			logger.Err(err).Msg("Failed to connect to remote via UDP")
			time.Sleep(5 * time.Second)
			continue
		}
		log.Info().Msg("Connected to the endpoint")

		for {
			read, err := iface.RWC.Read(buffer)
			if err != nil {
				logger.Err(err).Msg("error while reading from virtual interface")
				continue
			}
			flog := extendLogWithPacketDetails(buffer[:read], logger)

			flog.Info().Msg("Read from network interface, sending through UDP connection...")
			_, err = udpConn.Write(buffer[:read])
			if err != nil {
				log.Err(err).Msg("error while writing UDP to endpoint")
				continue
			}
		}
	}
}

func extendLogWithPacketDetails(buff []byte, logger zerolog.Logger) zerolog.Logger {
	ipHeader, err := ipv4.ParseHeader(buff)
	if err != nil {
		logger.Err(err).Msg("failed to parse IP header")
	} else {
		logger = logger.With().Str("src", ipHeader.Src.String()).
			Str("dst", ipHeader.Dst.String()).
			Int("proto", ipHeader.Protocol).
			Int("id", ipHeader.ID).
			Logger()
	}
	return logger
}

func runClient(cfg PeerConfig) error {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	logger := zerolog.New(os.Stdout)
	logger.Info().Str("addr", cfg.LocalAddr).Msg("Client is starting...")

	logger.Info().Msg("Creating network interface...")
	iface, err := configureTUNInterface("tun667", cfg.IP, logger)
	if err != nil {
		return errors.Wrap(err, "failed to create virtual interface")
	}

	// TODO: configure routing here?

	logger.Info().Msg("Starting up connection...")
	err = endpointConnection(iface, cfg, logger)
	if err != nil {
		return errors.Wrap(err, "failed to setup connection")
	}

	return nil
}

func endpointConnection(iface *tun_tap.TunVInterface, cfg PeerConfig, log zerolog.Logger) error {
	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve local address")
	}
	endpointAddr, err := net.ResolveUDPAddr("udp", cfg.EndpointAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve endpoint address")
	}

	log = log.With().Str("endpoint-addr", endpointAddr.String()).Logger()

	listenAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve listen address")
	}

	udpListener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return errors.Wrap(err, "failed start udp listener")
	}

	//log.Info().Msg("Connecting to the endpoint...")
	//udpConn, err := net.DialUDP("udp", localAddr, endpointAddr)
	//if err != nil {
	//	return errors.Wrap(err, "failed to connect to endpoint")
	//}

	log.Info().Msg("Connection successful")

	go udpReadAndForward(udpListener, iface, log)
	go tunReadAndForward(localAddr, endpointAddr, iface, log)

	// TODO: handle interupts etc
	<-make(chan string)
	return nil
}

func configureTUNInterface(name string, ip string, log zerolog.Logger) (*tun_tap.TunVInterface, error) {
	ifaceCfg := tun_tap.Config{
		Name:                   name,
		DeviceType:             tun_tap.TUN,
		PlatformSpecificParams: tun_tap.PlatformSpecificParams{},
		Persist:                false,
	}

	log.Info().Msg("Creating network interface...")
	iface, err := tun_tap.OpenDev(ifaceCfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create virtual interface")
	}

	err = ipcfg.SetupInterface(name, ip)
	if err != nil {
		return nil, errors.Wrap(err, "failed to configure interface")
	}

	// TODO: configure routing?

	return iface, nil
}
