package main

import (
	"bufio"
	"fmt"
	"github.com/szymongib/net-work/go-net-work/pkg/ipcfg"
	"github.com/szymongib/net-work/go-net-work/pkg/tun-tap"
	"log"
	"net"
	"os"
)

const (
	bufferSize = 1500
)

var (
	localIP  = "172.16.0.1/12"
	remoteIP = "8.8.8.8:53"
)

func main() {
	// Create virtual interface

	ifaceName := "tun9"
	listenUDPPort := "4321"

	cfg := tun_tap.Config{
		Name:       ifaceName,
		DeviceType: tun_tap.TUN,
		Driver:     tun_tap.MacOSDriverSystem,
	}

	iface, err := tun_tap.OpenDev(cfg)
	if err != nil {
		panic(err)
	}

	fmt.Println("Interface created: ", iface.Name)

	// For an interface to be operational you need to set it up
	/*
		ip link set dev tun0 mtu 1300
		ip addr add 192.168.9.10⁄24 dev tun0
		ip set dev tun0 up
	*/
	err = ipcfg.SetupInterface(ifaceName, localIP)
	if err != nil {
		panic(err)
	}

	// reslove remote addr
	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s", remoteIP))
	if nil != err {
		log.Fatalln("Unable to resolve remote addr:", err)
	}
	// listen to local socket
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", listenUDPPort))
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}
	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}
	defer lstnConn.Close()
	// recv in separate thread
	go func() {
		buf := make([]byte, bufferSize)
		for {
			n, addr, err := lstnConn.ReadFromUDP(buf)
			// just debug
			//header, _ := ipv4.ParseHeader(buf[:n])
			fmt.Printf("Received %d bytes from %v\n", n, addr)
			if err != nil || n == 0 {
				fmt.Println("Error: ", err)
				continue
			}
			// write to TUN interface
			_, err = iface.RWC.Write(buf[:n])
			if err != nil {
				fmt.Println("ERROR WRITING: ", err)
			}
		}
	}()
	// and one more loop
	packet := make([]byte, bufferSize)
	for {
		plen, err := iface.RWC.Read(packet)
		if err != nil {
			break
		}
		// debug :)
		//header, _ := ipv4.ParseHeader(packet[:plen])
		fmt.Printf("Sending to remote: (%+v)\n", "TODO")
		// real send
		lstnConn.WriteToUDP(packet[:plen], remoteAddr)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	fmt.Println("Bye!")

}
