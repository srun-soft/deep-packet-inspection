package packet_capture

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/record"
	"io"
	"net/http"
	"sync"
)

type httpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpStream
}

func (h *httpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *httpReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(h)
	for {
		if h.isClient {
			req, err := http.ReadRequest(b)
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				configs.Log.Errorf("HTTP-request HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}
			httpBson := &record.Http{
				Ident:         h.ident,
				SrcIP:         h.parent.src,
				DstIP:         h.parent.dst,
				Method:        req.Method,
				URL:           req.URL.String(),
				Proto:         req.Proto,
				Host:          req.Host,
				RemoteAddr:    req.RemoteAddr,
				RequestURI:    req.RequestURI,
				ContentType:   req.Header.Get("Content-Type"),
				ContentLength: req.Header.Get("Content-Length"),
				UserAgent:     req.UserAgent(),
				Delay:         h.parent.delay,
			}
			httpBson.Save2Mongo()
			body, err := io.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				configs.Log.Errorf("HTTP-request-body Got body err: %s \n", err)
			} else if h.hexdump {
				configs.Log.Debugf("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			_ = req.Body.Close()
			configs.Log.Debugf("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)
			h.parent.Lock()
			h.parent.urls = append(h.parent.urls, req.URL.String())
			h.parent.Unlock()
		} else {
			res, err := http.ReadResponse(b, nil)
			var req string
			h.parent.Lock()
			if len(h.parent.urls) == 0 {
				req = fmt.Sprintf("<no-request-seen>")
			} else {
				req, h.parent.urls = h.parent.urls[0], h.parent.urls[1:]
			}
			h.parent.Unlock()
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				configs.Log.Errorf("HTTP-response HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}
			body, err := io.ReadAll(res.Body)
			s := len(body)
			if err != nil {
				configs.Log.Errorf("HTTP-response-body HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err)
			}
			if h.hexdump {
				configs.Log.Debugf("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			_ = res.Body.Close()
			sym := ","
			if res.ContentLength > 0 && res.ContentLength != int64(s) {
				sym = "!="
			}
			contentType, ok := res.Header["Content-Type"]
			if !ok {
				contentType = []string{http.DetectContentType(body)}
			}
			encoding := res.Header["Content-Encoding"]
			configs.Log.Debugf("HTTP/%s Response: %s URL:%s (%d%s%d%s) -> %s\n", h.ident, res.Status, req, res.ContentLength, sym, s, contentType, encoding)
		}
	}
}
