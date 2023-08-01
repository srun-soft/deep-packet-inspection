package packet_capture

import (
	"fmt"
	"github.com/google/gopacket/pcap"
)

func init() {
	FindAllDev()
}

func FindAllDev() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		_ = fmt.Errorf("find all devs err:%v", err)
	}
	for _, item := range ifs {
		fmt.Printf("Name:%s\n", item.Name)
		fmt.Printf("Description:%s\n", item.Description)
		fmt.Printf("Flags:%d\n", item.Flags)
		for _, addr := range item.Addresses {
			fmt.Printf("IP:%s\n", addr.IP)
			fmt.Printf("NetMask:%s\n", addr.Netmask)
			fmt.Printf("Broadaddr:%s\n", addr.Broadaddr)
			fmt.Printf("P2P:%s\n", addr.P2P)
		}
	}
}
