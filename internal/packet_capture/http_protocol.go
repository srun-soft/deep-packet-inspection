package packet_capture

import (
	"bufio"
	"encoding/hex"
	"errors"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"io"
	"net/http"
)

func (sr *StreamReader) HTTP(b *bufio.Reader) bool {
	if sr.isClient {
		req, err := http.ReadRequest(b)
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			// TODO print io.EOF
			return false
		} else if err != nil {
			configs.Log.Errorf("HTTP-request HTTP Request error: %s (%v,%+v)\n", err, err, err)
			return false
		}
		body, err := io.ReadAll(req.Body)
		s := len(body)
		if err != nil {
			configs.Log.Errorf("HTTP-request-body Got body err: %s\n", err)
			return false
		}
		configs.Log.Info("HTTP Request Hex Dump\n", hex.Dump(body))
		_ = req.Body.Close()
		configs.Log.Errorf("HTTP/%s Request: %s %s (body:%d)\n", req.Method, req.URL, s)
		return true
	} else {
		res, err := http.ReadResponse(b, nil)
		var req string
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			// TODO print io.EOF
			return false
		} else if err != nil {
			configs.Log.Errorf("HTTP-response HTTP Response error: %s (%v,%+v)\n", err, err, err)
			return false
		}
		body, err := io.ReadAll(res.Body)
		s := len(body)
		if err != nil {
			configs.Log.Errorf("HTTP-response-body HTTP: failed to get body(parsed len:%d): %s\n", s, err)
			return false
		}
		configs.Log.Info("HTTP Response Hex Dump\n", hex.Dump(body))
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
		configs.Log.Infof("HTTP Response: %s URL:%s (%d%s%d%s) -> %s\n", res.Status, req, res.ContentLength, sym, s, contentType, encoding)
		return true
	}
}
