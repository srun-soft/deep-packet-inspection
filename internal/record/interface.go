package record

// packet interface
// Define protocol handling operations

// Protocol const

const (
	ProtocolHTTP  = "protocol_http"
	ProtocolHTTPS = "protocol_https"
	ProtocolDNS   = "protocol_dns"
	ProtocolICMP  = "protocol_icmp"
)

type Protocol interface {
	Parse()
	Save2Mongo()
}
