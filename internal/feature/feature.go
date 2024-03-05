package feature

import (
	"bufio"
	"github.com/cloudflare/ahocorasick"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"os"
	"regexp"
	"strings"
)

var (
	AppFeatures []App
	Ac          *ahocorasick.Matcher
	HostFeature []string
	HostMap     = make(map[int]string)
)

type App struct {
	Id       string
	Name     string
	Features []Feature
}

type Feature struct {
	Proto   string `json:"proto" comment:"协议"`
	SPort   string `json:"s_port" comment:"源端口"`
	DPort   string `json:"d_port" comment:"目标端口"`
	Host    string `json:"host" comment:"域名"`
	Request string `json:"request"`
	Dict    string `json:"dict" comment:"负载特征"`
}

// load feature. 加载特征库
func init() {
	file, err := os.Open(*configs.FeatureFile)
	if err != nil {
		configs.Log.Fatal("os open err:", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parseFeature(line)
	}
	Ac = ahocorasick.NewStringMatcher(HostFeature)
}

func parseFeature(line string) {
	re := regexp.MustCompile(`(\d+) (.+):\[(.+)]`)
	match := re.FindStringSubmatch(line)
	if len(match) == 0 {
		return
	}

	var app App
	app.Id = match[1]
	app.Name = match[2]
	temp := match[3]

	contents := strings.Split(temp, ",")
	for _, item := range contents {
		str := strings.Split(item, ";")
		if len(str) != 6 {
			continue
		}
		f := Feature{
			str[0],
			str[1],
			str[2],
			str[3],
			str[4],
			str[5],
		}
		if len(f.Host) > 0 {
			HostFeature = append(HostFeature, f.Host)
			HostMap[len(HostFeature)-1] = app.Name
			// .替换为空再插入

			dot := strings.Count(f.Host, ".")
			if dot >= 2 {
				var host string
				parts := strings.Split(f.Host, ".")
				// 去掉前缀,并且忽略大量相同的二级域名
				if parts[len(parts)-1] != "qq" && parts[len(parts)-1] != "com" {
					host = strings.TrimPrefix(f.Host, parts[0]+".")
					HostFeature = append(HostFeature, host)
					HostMap[len(HostFeature)-1] = app.Name
				}
				// 去掉后缀
				host = strings.TrimSuffix(f.Host, "."+parts[len(parts)-1])
				HostFeature = append(HostFeature, host)
				HostMap[len(HostFeature)-1] = app.Name
			}
		}
		app.Features = append(app.Features, f)
	}
	AppFeatures = append(AppFeatures, app)
}
