package protocol

import (
	"bufio"
	"errors"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"io"
	"net/http"
)

// Protocol HTTP

func C2s(b *bufio.Reader) {
	req, err := http.ReadRequest(b)
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		// TODO print io.EOF
		return
	} else if err != nil {
		configs.Log.Errorf("HTTP-request HTTP Request error: %s (%v,%+v)\n", err, err, err)
		return
	}
	body, err := io.ReadAll(req.Body)
	s := len(body)
	if err != nil {
		configs.Log.Errorf("HTTP-request-body Got body err: %s\n", err)
		return
	}
	_ = req.Body.Close()
	configs.Log.Errorf("HTTP/%s Request: %s %s (body:%d)\n", req.Method, req.URL, s)
	return
}

func S2c(b *bufio.Reader) {
	res, err := http.ReadResponse(b, nil)
	var req string
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		// TODO print io.EOF
		return
	} else if err != nil {
		configs.Log.Errorf("HTTP-response HTTP Response error: %s (%v,%+v)\n", err, err, err)
		return
	}
	body, err := io.ReadAll(res.Body)
	s := len(body)
	if err != nil {
		configs.Log.Errorf("HTTP-response-body HTTP: failed to get body(parsed len:%d): %s\n", s, err)
		return
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
	configs.Log.Infof("HTTP Response: %s URL:%s (%d%s%d%s) -> %s\n", res.Status, req, res.ContentLength, sym, s, contentType, encoding)
}
