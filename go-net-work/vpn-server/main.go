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

	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v2"
)

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
						Name:  "ip",
						Value: "172.16.0.1/24",
					},
				},
				Action: func(ctx *cli.Context) error {
					addr := ctx.String("addr")
					ip := ctx.String("ip")
					return runServer(addr, ip)
				},
			},
			{
				Name:    "client",
				Aliases: []string{"c"},
				Usage:   "You really need this?.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "addr",
						Value: "0.0.0.0:55510",
					},
					&cli.StringFlag{
						Name:  "endpoint-addr",
						Value: "127.0.0.1:55555",
					},
					&cli.StringFlag{
						Name:  "ip",
						Value: "172.16.0.2/24",
					},
				},
				Action: func(ctx *cli.Context) error {
					clientCfg := ClientConfig{
						EndpointAddr: ctx.String("endpoint-addr"),
						LocalAddr:    ctx.String("addr"),
						IP:           ctx.String("ip"),
					}
					return runClient(clientCfg)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Err(err).Msg("error while running app")
	}
}

func runServer(listenAddr, ip string) error {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	logger := zerolog.New(os.Stdout)
	logger.Info().Str("addr", listenAddr).Msg("Preparing server...")

	logger.Info().Msg("Creating network interface...")
	iface, err := configureTUNInterface("tun666", ip, logger)
	if err != nil {
		return errors.Wrap(err, "failed to configure virtual interface")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve UDP address")
	}

	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return errors.Wrap(err, "failed to startup UDP listener")
	}

	go func() {
		buffer := make([]byte, 2048) // TODO: have no idea how big the buffer should be
		logger := logger.With().Str("module", "udp-listener").Logger()
		logger.Info().Str("addr", listenAddr).Msg("Starting to listen...")

		for {
			read, addr, err := udpListener.ReadFromUDP(buffer)
			if err != nil {
				logger.Err(err).Msg("error while reading from UDP")
				continue
			}
			logger = logger.With().Str("peer", addr.String()).Logger()
			logger.Info().Int("read", read).Msg("received UDP packets")

			logger.Info().Msg("Writing to virtual interface")

			_, err = iface.RWC.Write(buffer[:read])
			if err != nil {
				logger.Err(err).Msg("error while writing to virtual interface")
				continue
			}

			// addr will be the peer address, so you need to send there the data
			// you get back from internets
		}

	}()

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
	return nil
}

func handlePacket() {

}

type ClientConfig struct {
	EndpointAddr string
	LocalAddr    string
	IP           string
}

func runClient(cfg ClientConfig) error {
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

func endpointConnection(iface *tun_tap.TunVInterface, cfg ClientConfig, log zerolog.Logger) error {
	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve local address")
	}
	endpointAddr, err := net.ResolveUDPAddr("udp", cfg.EndpointAddr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve endpoint address")
	}

	log = log.With().Str("endpoint-addr", endpointAddr.String()).Logger()

	log.Info().Msg("Connecting to the endpoint...")
	udpConn, err := net.DialUDP("udp", localAddr, endpointAddr)
	if err != nil {
		return errors.Wrap(err, "failed to connect to endpoint")
	}

	log.Info().Msg("Connection successful")

	go func() {
		buffer := make([]byte, 2048) // TODO: have no idea how big the buffer should be

		for {
			read, addr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				log.Err(err).Msg("error while reading from UDP")
				continue
			}

			fmt.Println("READ FROM: ", addr.String(), " : ", string(buffer[:read]))
		}
	}()

	go func() {
		buffer := make([]byte, 2048) // TODO: have no idea how big the buffer should be

		for {
			read, err := iface.RWC.Read(buffer)
			if err != nil {
				log.Err(err).Msg("error while reading from network interface")
				continue
			}
			log.Info().Int("read", read).Str("content", string(buffer[:read])).Msg("Bytes read from network interface, sending through UDP...")

			_, err = udpConn.Write(buffer[:read])
			if err != nil {
				log.Err(err).Msg("error while writing UDP to endpoint")
				continue
			}
		}

	}()

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
