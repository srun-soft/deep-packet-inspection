package packet_capture

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/sirupsen/logrus"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/record"
	"net"
	"strings"
	"sync"
	"time"
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
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		isHTTP:     strings.Contains(tcp.DstPort.String(), "80") && factory.doHTTP,
		isTLS:      tcp.DstPort == 443,
		reversed:   tcp.SrcPort == 80,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		src:        net.Src().Raw(),
		dst:        net.Dst().Raw(),
		optchecker: reassembly.NewTCPOptionCheck(),
		payload:    tcp.Payload,
		delay:      time.Now().Sub(ac.GetCaptureInfo().Timestamp),
	}
	if stream.isHTTP {
		stream.client = httpReader{
			bytes:    make(chan []byte),
			ident:    fmt.Sprintf("%s %s", net, transport),
			hexdump:  true,
			parent:   stream,
			isClient: true,
		}
		stream.server = httpReader{
			bytes:   make(chan []byte),
			ident:   fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
			hexdump: true,
			parent:  stream,
		}
		factory.wg.Add(2)
		go stream.client.run(&factory.wg)
		go stream.server.run(&factory.wg)
	}
	if stream.isTLS {
		stream.handshake = tlsReader{
			ident:  fmt.Sprintf("%s %s", net, transport),
			bytes:  make(chan []byte),
			parent: stream,
		}
		factory.wg.Add(1)
		go stream.handshake.run(&factory.wg)
	}
	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

/*
 * TCP stream
 */
/* It's a connection (bidirectional) */
type tcpStream struct {
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	isHTTP         bool
	reversed       bool
	client         httpReader
	server         httpReader
	handshake      tlsReader
	urls           []string
	hostname       string
	ident          string
	src            net.IP
	dst            net.IP
	prevTimeStamp  time.Time
	isTLS          bool
	payload        gopacket.Payload
	startTime      time.Time
	endTime        time.Time
	startPID       int
	endPID         int
	upStream       int
	downStream     int
	packageCount   int
	delay          time.Duration
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		//configs.Log.Errorf("FSM %s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			stats.rejectConnFsm++
		}

	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		configs.Log.Errorf("OptionChecker %s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		stats.rejectOpt++
	}
	// Checksum
	accept := true
	c, err := tcp.ComputeChecksum()
	if err != nil {
		configs.Log.Errorf("ChecksumCompute %s: Got error computing checksum: %s\n", t.ident, err)
		accept = false
	} else if c != 0x0 {
		configs.Log.Errorf("Checksum %s: Invalid checksum: 0x%x\n", t.ident, c)
		accept = false
	}
	if !accept {
		stats.rejectOpt++
	}
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	t.packageCount++
	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		stats.missedBytes += skip
	}
	stats.sz += length - saved
	stats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		stats.reassembled++
	}
	stats.outOfOrderPackets += sgStats.QueuedPackets
	stats.outOfOrderBytes += sgStats.QueuedBytes
	if length > stats.biggestChunkBytes {
		stats.biggestChunkBytes = length
	}
	if sgStats.Packets > stats.biggestChunkPackets {
		stats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		configs.Log.Infof("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	stats.overlapBytes += sgStats.OverlapBytes
	stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	configs.Log.Debugf("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 {
		// TODO this is allowed
	} else if skip != 0 {
		// TODO Missing bytes in stream: do not even try to Parse it
		return
	}
	if dir {
		// 上行流量
		t.upStream += length
	} else {
		t.downStream += length
	}
	if start {
		t.startTime = ac.GetCaptureInfo().Timestamp
		t.startPID = COUNT
	} else {
		t.endTime = ac.GetCaptureInfo().Timestamp
		t.endPID = COUNT
	}
	data := sg.Fetch(length)
	if t.isHTTP {
		if length > 0 {
			// configs.Log.Debugf("Feeding http with:\n%s", hex.Dump(data))
			if dir == reassembly.TCPDirClientToServer {
				t.client.bytes <- data
			} else {
				t.server.bytes <- data
			}
		}
	} else if t.isTLS {
		if length > 0 {
			t.handshake.bytes <- data
		}
	}
}

func (t *tcpStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	configs.Log.Debugf("%s: Connection closed\n", t.ident)
	if t.isHTTP {
		close(t.client.bytes)
		close(t.server.bytes)
	}
	if t.isTLS {
		if len(t.hostname) > 0 {
			httpsBson := &record.Tls{
				SrcIP:      t.src,
				DstIP:      t.dst,
				Host:       t.hostname,
				Ident:      t.ident,
				UpStream:   t.upStream,
				DownStream: t.downStream,
				StartTime:  t.startTime,
				EndTime:    t.endTime,
				Delay:      t.delay,
			}
			httpsBson.Save2Mongo()
		}
		close(t.handshake.bytes)
	}
	// do not remove the connection to allow last ack
	return false
}
