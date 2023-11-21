package configs

import (
	"fmt"
	format "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
	"time"
)

func initLog() {
	Log = logrus.New()

	if Debug {
		Log.SetLevel(logrus.DebugLevel)
	} else {
		Log.SetLevel(logrus.InfoLevel)
	}

	Log.SetFormatter(&format.Formatter{
		HideKeys:        false,
		TimestampFormat: time.RFC3339,
		FieldsOrder:     []string{"component", "category"},
	})

	Log.WithField("Log组件加载成功", fmt.Sprintf("DEBUG模式:%t", Debug)).Info()
}
