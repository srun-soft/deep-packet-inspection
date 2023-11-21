package packet_capture

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/olekukonko/tablewriter"
	"os"
)

type radiusReader struct {
	*layers.RADIUS
}

func (r *radiusReader) Read(p []byte) (n int, err error) {
	return n, nil
}

// FormatValue 格式化属性
func FormatValue(t layers.RADIUSAttributeType, l layers.RADIUSAttributeLength, v []byte) string {
	switch t {
	case layers.RADIUSAttributeTypeUserPassword, layers.RADIUSAttributeTypeCHAPPassword, layers.RADIUSAttributeTypeCHAPChallenge:
		// TODO 密码
		return ""
	case layers.RADIUSAttributeTypeNASIPAddress, layers.RADIUSAttributeTypeFramedIPAddress:
		return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
	case layers.RADIUSAttributeTypeServiceType:
		return ""
	default:
		if l == 6 {
			return fmt.Sprintf("%d", int(binary.BigEndian.Uint32(v)))
		} else {
			return string(v)
		}
	}
}

func (r *radiusReader) run() {
	if r.Code == layers.RADIUSCodeAccessRequest || r.Code == layers.RADIUSCodeAccountingRequest {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Type", "Value"})
		for _, item := range r.Attributes {
			if item.Type == layers.RADIUSAttributeTypeVendorSpecific {
				continue
			}
			table.Append([]string{item.Type.String(), FormatValue(item.Type, item.Length, item.Value)})
		}

		table.Render()
	}

}
