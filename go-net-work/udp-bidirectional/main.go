package main

import (
	"bufio"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Println("expected 2 arguments: [source port] [destination address]")
		os.Exit(1)
	}

	srcPort := args[0]
	dest := args[1]

	destAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		panic(err)
	}

	srcAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%s", srcPort))
	if err != nil {
		panic(err)
	}

	cnn, err := net.DialUDP("udp", srcAddr, destAddr)
	if err != nil {
		panic(err)
	}

	go readUDP(cnn)
	go writeUDP(cnn)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	fmt.Println("Bye!")
}

func readUDP(cnn *net.UDPConn) error {
	buff := make([]byte, 1024)

	for {
		read, addr, err := cnn.ReadFromUDP(buff)
		if err != nil {
			return errors.Wrap(err, "failed to read")
		}

		fmt.Println("<< [", addr.String(), "]: ", string(buff[:read]))
	}
}

func writeUDP(cnn *net.UDPConn) error {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")
		text, _ := reader.ReadString('\n')

		_, err := cnn.Write([]byte(text))
		if err != nil {
			return errors.Wrap(err, "failed to write")
		}

	}
}
