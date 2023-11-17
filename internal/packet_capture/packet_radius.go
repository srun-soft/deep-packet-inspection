package packet_capture

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/olekukonko/tablewriter"
	"os"
)

type RadiusPacket struct {
	layers.RADIUS
}

func FormatValue(t layers.RADIUSAttributeType, v []byte) string {
	switch t {
	case layers.RADIUSAttributeTypeUserPassword, layers.RADIUSAttributeTypeCHAPPassword, layers.RADIUSAttributeTypeCHAPChallenge:
		// TODO 密码
		return ""
	case layers.RADIUSAttributeTypeNASPort:
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(v))
	case layers.RADIUSAttributeTypeNASIPAddress, layers.RADIUSAttributeTypeFramedIPAddress:
		return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
	case layers.RADIUSAttributeTypeServiceType:
		return ""

	default:
		return string(v)
	}
}

func (p *RadiusPacket) Run() {
	if p.Code == layers.RADIUSCodeAccessRequest || p.Code == layers.RADIUSCodeAccountingRequest {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Type", "Value"})
		for _, item := range p.Attributes {
			table.Append([]string{item.Type.String(), FormatValue(item.Type, item.Value)})
		}

		table.Render()
	}

}
