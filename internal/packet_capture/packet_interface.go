package packet_capture

// packet interface
// Define protocol handling operations

// Protocol const

const (
	ProtocolHTTP      = "protocol_http_%s"
	ProtocolHandShake = "protocol_hs_%s"
	ProtocolDNS       = "protocol_dns_%s"
)

type Protocol interface {
	save()
}
