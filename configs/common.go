package configs

import (
	"flag"
	"github.com/sirupsen/logrus"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/ethernet"
)

var (
	Log         *logrus.Logger
	Devices     = flag.String("devices", "", "获取设备列表")
	NIC         = flag.String("n", "en0", "Network interface controller")
	OfflineFile = flag.String("f", "", "offline filepath")

	Debug  bool
	OutPut bool
	Radius bool
	Defrag bool
	HTTP   bool
	TCP    bool
	DNS    bool
)

func init() {
	flag.BoolVar(&Debug, "d", false, "开启调试模式 true or false")
	flag.BoolVar(&OutPut, "o", false, "OutPut2Console")
	flag.BoolVar(&Radius, "r", false, "Radius Protocol")
	flag.BoolVar(&Defrag, "defrag", false, "Defrag IPv4 Protocol")
	flag.BoolVar(&HTTP, "http", false, "HTTP Protocol")
	flag.BoolVar(&TCP, "tcp", false, "TCP Protocol")
	flag.BoolVar(&DNS, "dns", false, "DNS Protocol")
	flag.Parse()
	initLog()

	if *Devices != "" {
		switch *Devices {
		case "all":
			ethernet.All()
		}
	}
}
