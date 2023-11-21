package packet_capture

import (
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/utils"
	"sync"
)

// tls 协议
// 通过 handshake 获取 hostname

type tlsReader struct {
	ident    string
	hostname string
	parent   *tcpStream
	bytes    chan []byte
}

func (t *tlsReader) Read(p []byte) (n int, err error) {
	return n, nil
}

func (t *tlsReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		data, ok := <-t.bytes
		if !ok {
			break
		}
		if len(data) < 42 || data[0] != 0x16 || data[5] != 0x01 {
			continue
		}
		hostname := utils.GetServerExtensionName(data[5:])
		if len(hostname) > 0 {
			t.parent.Lock()
			t.parent.hostname = hostname
			t.parent.Unlock()
		} else {
			continue
		}
		configs.Log.Warn("Server Host Indication is ", hostname)
	}
}
