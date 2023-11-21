package packet_capture

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/record"
	"os"
	"os/signal"
	"sync"
	"time"
)

const closeTimeout = time.Hour * 24 // Closing inactive: TODO: from CLI
const timeout = time.Minute * 5

var COUNT int
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

type Packet interface {
	run(wg *sync.WaitGroup)
}

func init() {
	defer util.Run()
	var handle *pcap.Handle
	var err error
	offline := false

	// 根据 OfflineFile 决定读取离线包还是网卡流量
	if *configs.OfflineFile != "" {
		if handle, err = pcap.OpenOffline(*configs.OfflineFile); err != nil {
			configs.Log.Fatal("PCAP OpenOffline error:", err)
		}
		offline = true
	} else {
		inactive, err := pcap.NewInactiveHandle(*configs.NIC)
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
	// BPF filter 流量条件过滤
	//if err = handle.SetBPFFilter("src host 117.89.176.67"); err != nil {
	//	//if err = handle.SetBPFFilter("src host 101.227.131.222"); err != nil {
	//	log.Fatal("BPF filter error:", err)
	//}
	var dec gopacket.Decoder
	var ok bool
	decoderName := fmt.Sprintf("%s", handle.LinkType())
	if dec, ok = gopacket.DecodersByLayerName[decoderName]; !ok {
		configs.Log.Fatalln("No decoder named", decoderName)
	}
	source := gopacket.NewPacketSource(handle, dec)
	source.NoCopy = true
	configs.Log.Info("Starting to read packets\n")
	COUNT = 0
	defragger := ip4defrag.NewIPv4Defragmenter()

	// 创建流重组连接池
	streamFactory := &tcpStreamFactory{doHTTP: configs.HTTP}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	for packet := range source.Packets() {
		COUNT++
		configs.Log.Infof("Packet Count:%d", COUNT)
		// defrag IPv4 packet IP碎片整理
		// ----------------------------
		if configs.Defrag {
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}
			ip4 := ipv4Layer.(*layers.IPv4)
			l := ip4.Length
			var newip4 *layers.IPv4
			if offline {
				// 离线包使用数据包中的时间戳
				newip4, err = defragger.DefragIPv4WithTimestamp(ip4, packet.Metadata().CaptureInfo.Timestamp)
			} else {
				// 在线分析使用当前时间
				newip4, err = defragger.DefragIPv4(ip4)
			}

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
				_ = nextDecoder.Decode(newip4.Payload, pb)
			}
		}
		// ----------------------------
		// TCP 流重组
		// ----------------------------
		if configs.TCP {
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
		}
		// ----------------------------
		// DNS 分析
		// ----------------------------
		if configs.DNS {
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}
			ip4 := ipv4Layer.(*layers.IPv4)
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				dns := dnsLayer.(*layers.DNS)
				dnsBson := &record.Dns{
					SrcIP:    ip4.SrcIP,
					DstIP:    ip4.DstIP,
					SrcIPStr: ip4.SrcIP.String(),
					DstIPStr: ip4.DstIP.String(),
					Host:     string(dns.Questions[0].Name),
					Type:     dns.Questions[0].Type.String(),
					Class:    dns.Questions[0].Class.String(),
				}
				dnsBson.Save2Mongo()
			}
		}
		// ----------------------------
		// Radius 协议
		// ----------------------------
		if configs.Radius {
			r := &layers.RADIUS{}
			radiusLayer := packet.Layer(layers.LayerTypeRADIUS)
			if radiusLayer != nil {
				r = radiusLayer.(*layers.RADIUS)
				radiusPacket := &radiusReader{
					r,
				}
				radiusPacket.run()
				continue
			}
			transport := packet.TransportLayer()
			if transport == nil {
				continue
			}
			if transport != nil && transport.TransportFlow().Dst().String() == "1813" && transport.TransportFlow().Src().String() == "1813" {
				configs.Log.Info(packet.ApplicationLayer())
				err = r.DecodeFromBytes(packet.ApplicationLayer().Payload(), gopacket.NilDecodeFeedback)
				if err != nil {
					configs.Log.Error("Error decoding Radius packet:", err)
					continue
				}
				radiusPacket := &radiusReader{
					r,
				}
				radiusPacket.run()
				continue
			}
		}
		// ----------------------------

		if COUNT%1000 == 0 {
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
			configs.Log.Println(os.Stderr, "\nCaught SIGINT: aborting\n")
			done = true
		default:
			// NOP: continue
		}
		if done {
			break
		}
	}

	closed := assembler.FlushAll()
	configs.Log.Debugf("Final flush: %d closed", closed)
	if configs.Debug {
		streamPool.Dump()
	}

	streamFactory.WaitGoRoutines()
	configs.Log.Debugf("%s\n", assembler.Dump())
	configs.Log.Printf("IPdefrag:\t\t%d\n", stats.ipdefrag)

	//table := tablewriter.NewWriter(os.Stdout)
	//table.SetHeader([]string{
	//	"field",
	//	"remark",
	//	"value",
	//})
	//data := [][]string{
	//	{"missed bytes", "丢失字节", strconv.Itoa(stats.missedBytes)},
	//	{"total packets", "总包数", strconv.Itoa(stats.pkt)},
	//	{"rejected FSM", "无法重组", strconv.Itoa(stats.rejectFsm)},
	//	{"rejected Options", "不支持的选项", strconv.Itoa(stats.rejectOpt)},
	//	{"reassembled bytes", "重组字节数", strconv.Itoa(stats.sz)},
	//	{"total TCP bytes", "tcp连接字节数", strconv.Itoa(stats.totalsz)},
	//	{"conn rejected FSM", "连接被拒", strconv.Itoa(stats.rejectConnFsm)},
	//	{"reassembled chunks", "重组块大小", strconv.Itoa(stats.reassembled)},
	//	{"out-of-order packets", "乱序数据包", strconv.Itoa(stats.outOfOrderPackets)},
	//	{"out-of-order bytes", "乱序字节", strconv.Itoa(stats.outOfOrderBytes)},
	//	{"biggest-chunk packets", "最大块数据包", strconv.Itoa(stats.biggestChunkPackets)},
	//	{"biggest-chunk bytes", "最大字节数", strconv.Itoa(stats.biggestChunkBytes)},
	//	{"overlap packets", "重叠数据包", strconv.Itoa(stats.overlapPackets)},
	//	{"overlap bytes", "重叠字节", strconv.Itoa(stats.overlapBytes)},
	//}
	//table.AppendBulk(data)
	//table.Render()

	//tlsTable := tablewriter.NewWriter(os.Stdout)
	//tlsTable.SetHeader([]string{"ident", "host", "up(bytes)", "down(bytes)", "startTime", "endTime", "startPID", "endPID", "totalPacket"})
	//for _, v := range tls {
	//	tlsTable.Append(v)
	//}
	//tlsTable.Render()
}
