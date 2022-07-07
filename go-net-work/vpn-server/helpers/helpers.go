package helpers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"net"
)

// TODO: idealy without slice allocation
func SwapIPv4SrcAddr(rawPacket []byte, newAddr net.IP) ([]byte, error) {
	packet := gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)
	//fmt.Println(packet2.Dump())

	networkL := packet.NetworkLayer()
	ipv4Layer := networkL.(*layers.IPv4)
	ipv4Layer.SrcIP = newAddr

	buff := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buff, gopacket.SerializeOptions{ComputeChecksums: true}, ipv4Layer)
	//if err != nil {
	//	return nil, errors.Wrap(err, "failed to serialize ip layer")
	//}

	// TODO: do the same for tcp?
	if udp, ok := packet.TransportLayer().(*layers.UDP); ok {
		err := udp.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set network layer for checksum")
		}
	}

	err := gopacket.SerializePacket(buff, gopacket.SerializeOptions{ComputeChecksums: true}, packet)
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize modified packet")
	}

	return buff.Bytes(), nil
}
