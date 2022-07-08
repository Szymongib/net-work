package helpers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"net"
)

// TODO: idealy without slice allocation
func SwapSrcIPv4OutsideNet(rawPacket []byte, internalNet net.IPNet, newSrc net.IP) ([]byte, error) {
	packet := gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)

	networkL := packet.NetworkLayer()
	ipv4Layer := networkL.(*layers.IPv4)

	if internalNet.Contains(ipv4Layer.DstIP) {
		return rawPacket, nil
	}
	ipv4Layer.SrcIP = newSrc

	return SerializePacket(packet, ipv4Layer)
}

func SerializePacket(packet gopacket.Packet, netLayer gopacket.NetworkLayer) ([]byte, error) {
	buff := gopacket.NewSerializeBuffer()

	// TODO: do the same for tcp?
	if udp, ok := packet.TransportLayer().(*layers.UDP); ok {
		err := udp.SetNetworkLayerForChecksum(netLayer)
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
