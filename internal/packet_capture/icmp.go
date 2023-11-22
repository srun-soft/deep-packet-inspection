package packet_capture

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/record"
	"net"
	"sync"
	"time"
)

var (
	IcmpMap sync.Map
	// Description icmp
	Description = map[uint8]map[uint8]string{
		0: {
			0: "Echo ping Reply",
		},
		3: {
			0:  "Network Unreachable",
			1:  "Host Unreachable",
			2:  "Protocol Unreachable",
			3:  "Port Unreachable",
			4:  "Fragmentation needed but no frag. bit set",
			5:  "Source routing failed",
			6:  "Destination network unknown",
			7:  "Destination host unknown",
			9:  "Destination network administratively prohibited",
			10: "Destination host administratively prohibited",
			11: "Network unreachable for TOS",
			12: "Host unreachable for TOS",
			13: "Communication administratively prohibited by filtering",
			14: "Host precedence violation",
			15: "Precedence cutoff in effect",
		},
		4: {
			0: "Source quench",
		},
		5: {
			0: "Redirect for network",
			1: "Redirect for host",
			2: "Redirect for TOS and network",
			3: "Redirect for TOS and host",
		},
		8: {
			0: "Echo request",
		},
		9: {
			0: "Router advertisement",
		},
		10: {
			0: "Route solicitation",
		},
		11: {
			0: "TTL equals 0 during transit",
			1: "TTL equals 0 during reassembly",
		},
		12: {
			0: "IP header bad (catchall error)",
			1: "Required options missing",
		},
		17: {
			0: "Address mask request",
		},
		18: {
			0: "Address mask reply",
		},
	}
)

type IcmpReader struct {
	srcIP       net.IP
	dstIP       net.IP
	ttl         uint8
	time        time.Time
	description string
	delay       time.Duration
	layers      *layers.ICMPv4
}

func (i *IcmpReader) run() {
	req := fmt.Sprintf("%s->%s", i.srcIP, i.dstIP)
	rep := fmt.Sprintf("%s->%s", i.dstIP, i.srcIP)
	i.description = Description[i.layers.TypeCode.Type()][i.layers.TypeCode.Code()]
	switch i.layers.TypeCode.Type() {
	case 0:
		// Echo Reply
		reqTime, ok := IcmpMap.Load(rep)
		if !ok {
			return
		}
		i.delay = i.time.Sub(reqTime.(time.Time))
		IcmpMap.Delete(rep)
	// Redirect
	case 8:
		// Echo Request
		IcmpMap.LoadOrStore(req, i.time)
	}
	icmp := &record.Icmp{
		Ident:       req,
		SrcIP:       i.srcIP,
		DstIP:       i.dstIP,
		SrcIPStr:    i.srcIP.String(),
		DstIPStr:    i.dstIP.String(),
		Type:        i.layers.TypeCode.Type(),
		Code:        i.layers.TypeCode.Code(),
		TTL:         i.ttl,
		Description: i.description,
		Delay:       i.delay,
	}
	icmp.Save2Mongo()
}
