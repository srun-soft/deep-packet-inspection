package packet_capture

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/sirupsen/logrus"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"sync"
)

// Context The assembler context
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

/**
 * The TCP factory: returns new Stream
 */
type tcpStreamFactory struct {
	wg     sync.WaitGroup
	doHTTP bool
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	configs.Log.WithFields(logrus.Fields{
		"net":          net,
		"transport":    transport,
		"packetCounts": COUNT,
	}).Info("* NEW:")
	fsmOptions := reassembly.TCPSimpleFSMOptions{SupportMissingEstablishment: true}

	stream := &TCPStream{
		net:        net,
		transport:  transport,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
	}
	stream.client = StreamReader{
		bytes:    make(chan []byte),
		isClient: true,
		ident:    fmt.Sprintf("%s %s", net, transport),
		parent:   stream,
		src:      net.Src().String(),
		dst:      net.Dst().String(),
		srcPort:  transport.Src().String(),
		dstPort:  transport.Dst().String(),
		protocol: "tcp",
	}
	stream.server = StreamReader{
		bytes:    make(chan []byte),
		isClient: false,
		ident:    fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
		parent:   stream,
		src:      net.Reverse().Src().String(),
		dst:      net.Reverse().Dst().String(),
		srcPort:  transport.Reverse().Src().String(),
		dstPort:  transport.Reverse().Dst().String(),
		protocol: "tcp",
	}
	factory.wg.Add(2)
	go stream.client.run(&factory.wg)
	go stream.server.run(&factory.wg)
	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}
