package helpers

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"net"
	"testing"
)

func TestIPPacket(t *testing.T) {
	raw := []byte{
		69, 0, 0, 84, 251, 249, 64, 0, 64, 1, 230, 139, 172, 16, 0, 2, 172, 16, 0, 1, 8, 0, 195, 53, 0, 21, 0, 1, 143, 143, 198, 98, 0, 0, 0, 0, 18, 239, 13, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
	}

	ipHeader, err := ipv4.ParseHeader(raw)
	require.NoError(t, err)
	assert.Equal(t, "172.16.0.2", ipHeader.Src.String())
	assert.Equal(t, "172.16.0.1", ipHeader.Dst.String())

	marshalled, err := ipHeader.Marshal()
	require.NoError(t, err)

	fullPacket := append(marshalled, raw[len(marshalled):]...)

	assert.Equal(t, raw, fullPacket)
}

func TestSwapIPv4SrcAddr(t *testing.T) {
	// Initial source address is 172.16.0.2
	for _, testCase := range []struct {
		description string
		rawPacket   []byte
	}{
		{
			description: "udp packet",
			rawPacket: []byte{
				69, 0, 0, 60, 59, 102, 0, 0, 6, 17, 33, 40, 172, 16, 0, 2, 172, 16, 0, 1, 218, 205, 130, 169, 0, 40, 84, 254, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
			},
		},
		{
			description: "icmp (ping) packet",
			rawPacket: []byte{
				69, 0, 0, 84, 251, 249, 64, 0, 64, 1, 230, 139, 172, 16, 0, 2, 172, 16, 0, 1, 8, 0, 195, 53, 0, 21, 0, 1, 143, 143, 198, 98, 0, 0, 0, 0, 18, 239, 13, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
			},
		},
		// TODO: test for TCP
	} {
		t.Run(testCase.description, func(t *testing.T) {
			newPacket, err := SwapIPv4SrcAddr(testCase.rawPacket, net.IPv4(192, 64, 16, 1))
			require.NoError(t, err)

			modified := gopacket.NewPacket(newPacket, layers.LayerTypeIPv4, gopacket.Default)
			networkL := modified.NetworkLayer()
			ipv4Layer := networkL.(*layers.IPv4)

			assert.Nil(t, modified.ErrorLayer())
			assert.Equal(t, "192.64.16.1", ipv4Layer.SrcIP.String())
		})
	}
}

func TestGoPacket(t *testing.T) {
	//raw := []byte{
	//	69, 0, 0, 84, 251, 249, 64, 0, 64, 1, 230, 139, 172, 16, 0, 2, 172, 16, 0, 1, 8, 0, 195, 53, 0, 21, 0, 1, 143, 143, 198, 98, 0, 0, 0, 0, 18, 239, 13, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
	//}

	raw2 := []byte{
		69, 0, 0, 60, 59, 102, 0, 0, 6, 17, 33, 40, 172, 16, 0, 2, 172, 16, 0, 1, 218, 205, 130, 169, 0, 40, 84, 254, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
	}
	r2 := make([]byte, len(raw2))
	copy(r2, raw2)

	//packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	packet2 := gopacket.NewPacket(raw2, layers.LayerTypeIPv4, gopacket.Default)
	fmt.Println(packet2.Dump())

	networkL := packet2.NetworkLayer()
	ipv4Layer := networkL.(*layers.IPv4)
	ipv4Layer.SrcIP = net.IPv4(192, 168, 64, 5)

	fmt.Println("Network layer: ", packet2.NetworkLayer().LayerType().String())
	fmt.Println("Transport layer: ", packet2.TransportLayer().LayerType().String())
	fmt.Println("Application layer: ", packet2.ApplicationLayer().LayerType().String())

	fmt.Println()
	fmt.Println()
	fmt.Println(packet2.Dump())

	assert.Equal(t, r2, raw2)

	//fmt.Println("Transport layer: ", packet.TransportLayer().LayerType().String())
	//fmt.Println("Network layer: ", packet.NetworkLayer().LayerType().String())
	//fmt.Println("Network layer: ", packet.TransportLayer().LayerType().String())
	//fmt.Println("Application layer: ", packet.ApplicationLayer().LayerType().String())

}
