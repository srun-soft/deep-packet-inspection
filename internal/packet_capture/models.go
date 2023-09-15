package packet_capture

import (
	"github.com/google/gopacket/layers"
	"net"
)

type Packet struct {
	LinkLayer
	NetworkLayer
	TransportLayer
	ApplicationLayer
}

type LinkLayer struct {
	SrcMac       net.HardwareAddr
	DstMac       net.HardwareAddr
	EthernetType layers.EthernetType
}

type NetworkLayer struct {
	Version  uint8
	Length   uint16
	Id       uint16
	TTL      uint8
	Protocol layers.IPProtocol
	Checksum uint16
	Src      net.IP
	Dst      net.IP
}

type TransportLayer struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	TcpLayer
}

type TcpLayer struct {
	Seq uint32
	Ack uint32
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

type ApplicationLayer struct {
	Payload []byte
}
