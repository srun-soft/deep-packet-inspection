package utils

import (
	"net"
	"strings"
)

// domain about

func Parse(h string) (domain, suffix string) {
	if h == "" {
		return
	}
	// 如果是ip直接返回
	if net.ParseIP(h) != nil {
		return
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
