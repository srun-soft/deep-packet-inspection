package packet_capture

// packet interface
// Define protocol handling operations

// Protocol const

const (
	ProtocolHttp = "protocol_http_%s"
	ProtocolHs   = "protocol_hs_%s"
)

type Protocol interface {
	save()
}
