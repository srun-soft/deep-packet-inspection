package packet_capture

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/record"
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

func (sr *StreamReader) Read(p []byte) (n int, err error) {
	ok := true
	for ok && len(sr.data) == 0 {
		sr.data, ok = <-sr.bytes
	}
	if !ok || len(sr.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, sr.data)
	sr.data = sr.data[l:]
	return l, nil
}

func (sr *StreamReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(sr)

	prefix, _ := b.Peek(12)
	if len(prefix) > 0 && checkHttpProtocol(prefix) {
		configs.Log.Info("Client bytes:\n", hex.Dump(prefix))
		sr.protocol = "http"
	}
	buf := make([]byte, 1024)
	for {
		if sr.isClient {
			// Client -> Server
			if sr.protocol == "http" {
				req, err := http.ReadRequest(b)
				if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				} else if err != nil {
					//configs.Log.Errorf("HTTP-request HTTP Request error: %s (%v,%+v)\n", err, err, err)
					continue
				}
				body, err := io.ReadAll(req.Body)
				s := len(body)
				if err != nil {
					configs.Log.Errorf("HTTP-request-body Got body err: %s\n", err)
					continue
				}
				t := map[string]interface{}{
					"ident":  sr.ident,
					"url":    req.URL,
					"method": req.Method,
					"host":   req.Host,
					"http":   "request",
				}
				sr.parent.Lock()
				sr.parent.urls = append(sr.parent.urls, req.URL.String())
				sr.parent.host = req.Host
				sr.parent.Unlock()
				_, err = database.MongoDB.Database(record.ProtocolHTTP).Collection("test").InsertOne(context.TODO(), t)
				if err != nil {
					configs.Log.Error("mongodb save error", err)
				}
				configs.Log.Info("HTTP Request Hex Dump\n", hex.Dump(body), "Body Length:", s)
				_ = req.Body.Close()
			} else {
				_, err := b.Read(buf)
				if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				} else if err != nil {
					break
				}
			}
		} else {
			// Server -> Client
			if sr.protocol == "http" {
				res, err := http.ReadResponse(b, nil)
				var req, host string
				sr.parent.Lock()
				if len(sr.parent.urls) == 0 {
					req = fmt.Sprintf("<no-requesr-seen>")
				} else {
					req, sr.parent.urls = sr.parent.urls[0], sr.parent.urls[1:]
				}
				host = sr.parent.host
				sr.parent.Unlock()
				if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				} else if err != nil {
					//configs.Log.Errorf("HTTP-request HTTP Request error: %s (%v,%+v)\n", err, err, err)
					continue
				}
				body, err := io.ReadAll(res.Body)
				s := len(body)
				if err != nil {
					configs.Log.Errorf("HTTP-response-body Got body err: %s\n", err)
					continue
				}
				t := map[string]interface{}{
					"ident":  sr.ident,
					"url":    req,
					"method": "",
					"host":   host,
					"http":   "response",
				}
				_, err = database.MongoDB.Database(record.ProtocolHTTP).Collection("test").InsertOne(context.TODO(), t)
				if err != nil {
					configs.Log.Error("mongodb save error", err)
				}
				configs.Log.Info("HTTP Request Hex Dump\n", hex.Dump(body), "Body Length:", s)
				_ = res.Body.Close()
			} else {
				_, err := b.Read(buf)
				if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				} else if err != nil {
					break
				}
			}
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
