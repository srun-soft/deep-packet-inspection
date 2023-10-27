package configs

import (
	"flag"
	"github.com/sirupsen/logrus"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/ethernet"
)

var (
	Log     *logrus.Logger
	Debug   = flag.Bool("debug", false, "开启调试模式 true or false")
	Devices = flag.String("devices", "", "获取设备列表")
	Iface   = flag.String("iface", "en0", "interface device")
	Fname   = flag.String("fname", "", "offline filepath")
	Output  = flag.String("output", "", "")
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
