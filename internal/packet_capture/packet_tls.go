package packet_capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"sync"
	"time"
)

// tls 协议
// 通过 handshake 获取 hostname

type tlsReader struct {
	ident    string
	hostname string
	parent   *tcpStream
	bytes    chan []byte
}

func (t *tlsReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("handshake")
	for {
		data, ok := <-t.bytes
		if !ok {
			break
		}
		if len(data) < 42 || data[0] != 0x16 || data[5] != 0x01 {
			continue
		}
		hostname := getServerExtensionName(data[5:])
		if len(hostname) > 0 {
			t.parent.Lock()
			t.parent.hostname = hostname
			t.parent.Unlock()
		} else {
			continue
		}
		configs.Log.Warn("Server Host Indication is ", hostname)
	}
}

type HTTPSBson struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Host       string             `bson:"host"`
	Domain     string             `bson:"domain"`
	Suffix     string             `bson:"suffix"`
	SrcIP      net.IP             `bson:"src_ip"`
	DstIP      net.IP             `bson:"dst_ip"`
	SrcIPStr   string             `bson:"src_ip_str"`
	DstIPStr   string             `bson:"dst_ip_str"`
	Ident      string             `bson:"ident"`
	UpStream   int                `bson:"up_stream"`
	DownStream int                `bson:"down_stream"`
	StartTime  time.Time          `bson:"start_time"`
	EndTime    time.Time          `bson:"end_time"`
}

func (h *HTTPSBson) Parse() {
	h.Domain, h.Suffix = utils.Parse(h.Host)
	h.SrcIPStr, h.DstIPStr = h.SrcIP.String(), h.DstIP.String()
}

func (h *HTTPSBson) Save2Mongo() {
	h.Parse()
	mongo := database.MongoDB.Database(ProtocolHTTPS)
	one, err := mongo.Collection(time.Now().Format("C_2006_01_02_15")).InsertOne(context.TODO(), h)
	if err != nil {
		configs.Log.Errorf("Save2Mongo protocol handshake2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("Save2Mongo protocol handshake2mongo id:%s", one)
}

// 获取SNI server name indication
func getServerExtensionName(data []byte) string {
	// Skip past fixed-length records:
	// 1  Handshake Type
	// 3  Length
	// 2  Version (again)
	// 32 Random
	// next Session ID Length
	pos := 38
	dataLen := len(data)

	/* session id */
	if dataLen < pos+1 {
		return ""
	}
	l := int(data[pos])
	pos += l + 1

	/* Cipher Suites */
	if dataLen < (pos + 2) {
		return ""
	}
	l = int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += l + 2

	/* Compression Methods */
	if dataLen < (pos + 1) {
		return ""
	}
	l = int(data[pos])
	pos += l + 1

	/* Extensions */
	if dataLen < (pos + 2) {
		return ""
	}
	l = int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	/* Parse extensions to get SNI */
	var extensionItemLen int

	/* Parse each 4 bytes for the extension header */
	for pos+4 <= l {
		extensionItemLen = int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if data[pos] == 0x00 && data[pos+1] == 0x00 {
			if (pos + 4 + extensionItemLen) > l {
				return ""
			}
			// get sni string
			pos += 6
			extensionEnd := pos + extensionItemLen - 2
			for pos+3 < extensionEnd {
				serverNameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
				if pos+3+serverNameLen > extensionEnd {
					return ""
				}

				switch data[pos] {
				case 0x00: //hostname
					hostname := make([]byte, serverNameLen)
					copy(hostname, data[pos+3:pos+3+serverNameLen])
					return string(hostname)
				default:
					fmt.Println("Encountered error! Debug me...")
				}

				pos += 3 + l
			}
		}
		pos += 4 + extensionItemLen
	}
	return ""
}
