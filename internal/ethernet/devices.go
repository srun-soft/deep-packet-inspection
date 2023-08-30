package ethernet

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/olekukonko/tablewriter"
	"net"
	"os"
	"strconv"
)

// devices 设备

// All 查找所有设备
func All() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("find All devices err:", err)
		return
	}

	fmt.Println("设备列表:")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "IPv4", "IPv6", "Flags"})

	for _, dev := range devs {
		var ipv4, ipv6 net.IP
		address := dev.Addresses
		for _, addr := range address {
			if len(addr.Netmask) == net.IPv6len {
				ipv6 = addr.IP
				continue
			}
			if len(addr.Netmask) == net.IPv4len {
				ipv4 = addr.IP
				continue
			}
		}
		table.Append([]string{dev.Name, ipv4.String(), ipv6.String(), strconv.Itoa(int(dev.Flags))})
	}

	table.Render()
}
