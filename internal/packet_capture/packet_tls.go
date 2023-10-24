package packet_capture

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
)

// tls 协议
// 通过 handshake 获取 hostname

func isTLSHandshake(packet gopacket.Packet) bool {
	payloadLayer := packet.ApplicationLayer()
	if payloadLayer != nil {
		// 检查有效载荷中是否包含了 TLS 握手信息的标志
		payload := payloadLayer.Payload()
		return len(payload) > 5 && payload[0] == 0x16 && payload[5] == 0x01
	}
	return false
}

func extractHostnameFromTLS(packet gopacket.Packet) (string, error) {
	payloadLayer := packet.ApplicationLayer()
	if payloadLayer == nil {
		return "", fmt.Errorf("not a TCP packet with payload")
	}

	// 解析 TCP 有效载荷中的TLS握手信息
	payload := payloadLayer.Payload()
	if len(payload) < 42 || payload[0] != 0x16 || payload[5] != 0x01 {
		return "", fmt.Errorf("not a TLS handshake")
	}

	temp := getServerExtensionName(payload[5:])
	fmt.Println(temp)
	return temp, nil
}

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
	//var extensionItemLen uint16

	/* Parse each 4 bytes for the extension header */
	return ""
}
