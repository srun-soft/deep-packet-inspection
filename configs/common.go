package configs

import (
	"flag"
	"github.com/sirupsen/logrus"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/ethernet"
)

var (
	Log         *logrus.Logger
	Debug       = flag.Bool("debug", false, "开启调试模式 true or false")
	Devices     = flag.String("devices", "", "获取设备列表")
	NIC         = flag.String("nic", "en0", "Network interface controller")
	OfflineFile = flag.String("of", "", "offline filepath")
	Output      = flag.String("output", "", "")
	Offline     bool
)

func init() {
	flag.Parse()
	initLog()

	if *Devices != "" {
		switch *Devices {
		case "all":
			ethernet.All()
		}
	}
}
