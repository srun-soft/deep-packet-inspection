package packet_capture

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"io"
	"net/http"
	"sync"
)

var Methods = []string{
	"HTTP",
	http.MethodGet,
	http.MethodPost,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

type StreamReader struct {
	parent   *TCPStream
	isClient bool
	bytes    chan []byte
	data     []byte
	ident    string
	src      string
	dst      string
	srcPort  string
	dstPort  string
	protocol string
}

func (s *StreamReader) Read(p []byte) (n int, err error) {
	ok := true
	for ok && len(s.data) == 0 {
		s.data, ok = <-s.bytes
	}
	if !ok || len(s.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, s.data)
	s.data = s.data[l:]
	return l, nil
}

func (s *StreamReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(s)

	prefix, _ := b.Peek(12)
	if len(prefix) > 0 && checkHttpProtocol(prefix) {
		configs.Log.Info("Client bytes:\n", hex.Dump(prefix))
		s.protocol = "http"
	}
	for {
		if s.isClient {
			// Client -> Server
			switch s.protocol {
			case "http":
			case "tls":

			}
			//req, err := http.ReadRequest(b)
		} else {
			// Server -> Client
			_, _ = b.ReadBytes('\n')
		}
	}
}

func checkHttpProtocol(line []byte) bool {
	for _, method := range Methods {
		if bytes.HasPrefix(line, []byte(method)) {
			return true
		}
	}
	return false
}
