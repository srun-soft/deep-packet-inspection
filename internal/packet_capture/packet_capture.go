package packet_capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"time"
)

var ()

const closeTimeout time.Duration = time.Hour * 24 // Closing inactive: TODO: from CLI
const timeout time.Duration = time.Minute * 5

var stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

type httpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpStream
}

func (h *httpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *httpReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(h)
	for true {
		if h.isClient {
			req, err := http.ReadRequest(b)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				configs.Log.Errorf("HTTP-request HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}
			body, err := io.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				configs.Log.Errorf("HTTP-request-body Got body err: %s \n", err)
			} else if h.hexdump {
				configs.Log.Info("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			req.Body.Close()
			configs.Log.Info("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)
			h.parent.Lock()
			h.parent.urls = append(h.parent.urls, req.URL.String())
			h.parent.Unlock()
		} else {
			res, err := http.ReadResponse(b, nil)
			var req string
			h.parent.Lock()
			if len(h.parent.urls) == 0 {
				req = fmt.Sprintf("<no-request-seen>")
			} else {
				req, h.parent.urls = h.parent.urls[0], h.parent.urls[1:]
			}
			h.parent.Unlock()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				configs.Log.Errorf("HTTP-response HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}
			body, err := io.ReadAll(res.Body)
			s := len(body)
			if err != nil {
				configs.Log.Errorf("HTTP-response-body HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err)
			}
			if h.hexdump {
				configs.Log.Infof("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			res.Body.Close()
			sym := ","
			if res.ContentLength > 0 && res.ContentLength != int64(s) {
				sym = "!="
			}
			contentType, ok := res.Header["Content-Type"]
			if !ok {
				contentType = []string{http.DetectContentType(body)}
			}
			encoding := res.Header["Content-Encoding"]
			configs.Log.Infof("HTTP/%s Response: %s URL:%s (%d%s%d%s) -> %s\n", h.ident, res.Status, req, res.ContentLength, sym, s, contentType, encoding)
			if *configs.Output != "" {
				base := url.QueryEscape(path.Base(req))
				if err != nil {
					base = "incomplete-" + base
				}
				base = path.Join(*configs.Output, base)
				if len(base) > 250 {
					base = base[:250] + "..."
				}
				if base == *configs.Output {
					base = path.Join(*configs.Output, "noname")
				}
				target := base
				n := 0
				for true {
					_, err := os.Stat(target)
					if err != nil {
						break
					}
					target = fmt.Sprintf("#{base}-#{n}")
					n++
				}
				f, err := os.Create(target)
				if err != nil {
					configs.Log.Errorf("HTTP-create Cannot create %s: %s\n", target, err)
					continue
				}
				var r io.Reader
				r = bytes.NewBuffer(body)
				if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
					r, err = gzip.NewReader(r)
					if err != nil {
						configs.Log.Errorf("HTTP-gunzip Failed to gzip decode: %s", err)
					}
				}
				if err == nil {
					w, err := io.Copy(f, r)
					if _, ok := r.(*gzip.Reader); ok {
						r.(*gzip.Reader).Close()
					}
					f.Close()
					if err != nil {
						configs.Log.Errorf("HTTP-save %s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
					} else {
						configs.Log.Infof("%s: Saved %s (l:%d)\n", h.ident, target, w)
					}
				}
			}
		}
	}
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
		"net":       net,
		"transport": transport,
	}).Debug("* NEW:")
	fsmOptions := reassembly.TCPSimpleFSMOptions{SupportMissingEstablishment: true}
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		isDNS:      tcp.SrcPort == 53 || tcp.DstPort == 53,
		isHTTP:     (tcp.SrcPort == 80 || tcp.DstPort == 80) && factory.doHTTP,
		reversed:   tcp.SrcPort == 80,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
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
	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

// Context The assembler context
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
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
	isDNS          bool
	isHTTP         bool
	reversed       bool
	client         httpReader
	server         httpReader
	urls           []string
	ident          string
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		configs.Log.Errorf("FSM %s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
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
		// TODO Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)
	if t.isDNS {
		dns := &layers.DNS{}
		var decoded []gopacket.LayerType
		if len(data) < 2 {
			if len(data) > 0 {
				sg.KeepFrom(0)
			}
			return
		}
		dnsSize := binary.BigEndian.Uint16(data[:2])
		missing := int(dnsSize) - len(data[2:])
		configs.Log.Debugf("dnsSize: %d, missing: %d\n", dnsSize, missing)
		if missing > 0 {
			configs.Log.Infof("Missing some bytes: %d\n", missing)
			sg.KeepFrom(0)
			return
		}
		p := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dns)
		err := p.DecodeLayers(data[2:], &decoded)
		if err != nil {
			configs.Log.Errorf("DNS-parser Failed to decoed DNS: %v\n", err)
		} else {
			configs.Log.Debugf("DNS: %s\n", gopacket.LayerDump(dns))
		}
		if len(data) > 2+int(dnsSize) {
			sg.KeepFrom(2 + int(dnsSize))
		}
	} else if t.isHTTP {
		if length > 0 {
			configs.Log.Debugf("Feeding http with:\n%s", hex.Dump(data))
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.bytes <- data
			} else {
				t.server.bytes <- data
			}
		}
	}
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	configs.Log.Debugf("%s: Connection closed\n", t.ident)
	if t.isHTTP {
		close(t.client.bytes)
		close(t.server.bytes)
	}
	// do not remove the connection to allow last ack
	return false
}

func init() {
	defer util.Run()
	var handle *pcap.Handle
	var err error
	if *configs.Fname != "" {
		if handle, err = pcap.OpenOffline(*configs.Fname); err != nil {
			configs.Log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		inactive, err := pcap.NewInactiveHandle(*configs.Iface)
		if err != nil {
			configs.Log.Fatalf("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(65536); err != nil {
			configs.Log.Fatalf("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(true); err != nil {
			configs.Log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			configs.Log.Fatalf("could not set timeout: %v", err)
		}
		if handle, err = inactive.Activate(); err != nil {
			configs.Log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
	}
	// TODO BPF filter

	var dec gopacket.Decoder
	var ok bool
	decoderName := fmt.Sprintf("%s", handle.LinkType())
	if dec, ok = gopacket.DecodersByLayerName[decoderName]; !ok {
		configs.Log.Fatalln("No decoder named", decoderName)
	}
	source := gopacket.NewPacketSource(handle, dec)
	source.NoCopy = true
	configs.Log.Info("Starting to read packets\n")
	count := 0
	bytes := int64(0)
	defragger := ip4defrag.NewIPv4Defragmenter()

	streamFactory := &tcpStreamFactory{doHTTP: true}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	for packet := range source.Packets() {
		count++
		configs.Log.Debugf("PACKET #%d\n", count)
		data := packet.Data()
		bytes += int64(len(data))
		configs.Log.Debugf("Packet content (%d/0x%x)\n%s\n", len(data), len(data), hex.Dump(data))

		// defrag IPv4 packet
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			continue
		}
		ip4 := ipv4Layer.(*layers.IPv4)
		l := ip4.Length
		newip4, err := defragger.DefragIPv4(ip4)
		if err != nil {
			configs.Log.Fatalln("Error while de-fragmenting", err)
		} else if newip4 == nil {
			configs.Log.Debug("Fragment...\n")
			continue // packet fragment, we don't have whole packet yet.
		}
		if newip4.Length != l {
			stats.ipdefrag++
			configs.Log.Debugf("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := newip4.NextLayerType()
			nextDecoder.Decode(newip4.Payload, pb)
		}
		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
			if err != nil {
				configs.Log.Fatalf("Failed to set network layer for checksum: %s\n", err)
			}
			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			stats.totalsz += len(tcp.Payload)
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}
		if count%1000 == 0 {
			ref := packet.Metadata().CaptureInfo.Timestamp
			flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{
				T:  ref.Add(-timeout),
				TC: ref.Add(-closeTimeout),
			})
			configs.Log.Debugf("Forced flush: %d flushed, %d closed (%s)", flushed, closed, ref)
		}
		done := false
		select {
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting\n")
			done = true
		default:
			// NOP: contine
		}
		if done {
			break
		}
	}

	closed := assembler.FlushAll()
	configs.Log.Debugf("Final flush: %d closed", closed)
	streamPool.Dump()

	streamFactory.WaitGoRoutines()
	configs.Log.Debugf("%s\n", assembler.Dump())
	configs.Log.Printf("IPdefrag:\t\t%d\n", stats.ipdefrag)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"field",
		"remark",
		"value",
	})
	data := [][]string{
		{"missed bytes", "丢失字节", strconv.Itoa(stats.missedBytes)},
		{"total packets", "总包数", strconv.Itoa(stats.pkt)},
		{"rejected FSM", "无法重组", strconv.Itoa(stats.rejectFsm)},
		{"rejected Options", "不支持的选项", strconv.Itoa(stats.rejectOpt)},
		{"reassembled bytes", "重组字节数", strconv.Itoa(stats.sz)},
		{"total TCP bytes", "tcp连接字节数", strconv.Itoa(stats.totalsz)},
		{"conn rejected FSM", "连接被拒", strconv.Itoa(stats.rejectConnFsm)},
		{"reassembled chunks", "重组块大小", strconv.Itoa(stats.reassembled)},
		{"out-of-order packets", "乱序数据包", strconv.Itoa(stats.outOfOrderPackets)},
		{"out-of-order bytes", "乱序字节", strconv.Itoa(stats.outOfOrderBytes)},
		{"biggest-chunk packets", "最大块数据包", strconv.Itoa(stats.biggestChunkPackets)},
		{"biggest-chunk bytes", "最大字节数", strconv.Itoa(stats.biggestChunkBytes)},
		{"overlap packets", "重叠数据包", strconv.Itoa(stats.overlapPackets)},
		{"overlap bytes", "重叠字节", strconv.Itoa(stats.overlapBytes)},
	}
	table.AppendBulk(data)
	table.Render()
}
