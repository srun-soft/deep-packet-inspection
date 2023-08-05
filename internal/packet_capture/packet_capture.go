package packet_capture

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"net/http"
	"time"
)

var (
	iface         = flag.String("i", "en0", "Interface to get packets from")
	fname         = flag.String("r", "", "Filename to read from, overrides -i")
	snaplen       = flag.Int("s", 1600, "SnapLen for pcap packet capture")
	filter        = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")
	logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run()

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}
func init() {
	defer util.Run()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}

	if err != nil {
		log.Fatal(err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}

	}
}

func FindAllDev() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		_ = fmt.Errorf("find all devs err:%v", err)
	}
	for _, item := range ifs {
		fmt.Printf("Name:%s\n", item.Name)
		fmt.Printf("Description:%s\n", item.Description)
		fmt.Printf("Flags:%d\n", item.Flags)
		for _, addr := range item.Addresses {
			fmt.Printf("IP:%s\n", addr.IP)
			fmt.Printf("NetMask:%s\n", addr.Netmask)
			fmt.Printf("Broadaddr:%s\n", addr.Broadaddr)
			fmt.Printf("P2P:%s\n", addr.P2P)
		}
	}
}
