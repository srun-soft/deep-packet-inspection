package packet_capture

import (
	"bufio"
	"errors"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"io"
	"net/http"
	"strings"
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
	parent *TCPStream
	bytes  chan []byte
	data   []byte
	ident  string
	src    string
	dst    string
}

func (s StreamReader) Read(p []byte) (n int, err error) {
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

func (s StreamReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	r := bufio.NewReader(s)
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			break
		}
		configs.Log.Info(line)
		if checkProtocolHttp(line) {
			configs.Log.Info("line ===> ", line)
		}
	}
}

func checkProtocolHttp(line string) bool {
	for _, method := range Methods {
		if strings.HasPrefix(line, method) {
			return true
		}
	}
	return false
}
