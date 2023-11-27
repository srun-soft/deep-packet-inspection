package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// domain about

func ParseHost(h string) (domain, suffix string) {
	if h == "" {
		return
	}
	if strings.Contains(h, ":") {
		host := strings.Split(h, ":")
		h = host[0]
	}
	// 如果是ip直接返回
	if net.ParseIP(h) != nil {
		return h, ""
	}
	parts := strings.Split(h, ".")
	if len(parts) > 2 {
		domain = parts[len(parts)-2]
		suffix = parts[len(parts)-1]
		// 如果主域名是 "com"，则可能有第三级域名
		if domain == "com" && len(parts) >= 3 {
			domain = parts[len(parts)-3]
		}
	}
	return domain, suffix
}

// GetServerExtensionName 获取SNI server name indication
func GetServerExtensionName(data []byte) string {
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
