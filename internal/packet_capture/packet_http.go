package packet_capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"
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
			r := &Request{req}
			r.save()
			body, err := io.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				configs.Log.Errorf("HTTP-request-body Got body err: %s \n", err)
			} else if h.hexdump {
				configs.Log.Info("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			_ = req.Body.Close()
			configs.Log.Info("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)
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
				configs.Log.Infof("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
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
			configs.Log.Infof("HTTP/%s Response: %s URL:%s (%d%s%d%s) -> %s\n", h.ident, res.Status, req, res.ContentLength, sym, s, contentType, encoding)
			if *configs.Output != "" {
				base := url.QueryEscape(path.Base(req))
				if err != nil {
					base = "incomplete-" + base
				}
				base = path.Join(*configs.Output, base)
				if len(base) > 250 {
					base = base[:250] + "..."
				}
				if base == *configs.Output {
					base = path.Join(*configs.Output, "noname")
				}
				target := base
				n := 0
				for true {
					_, err := os.Stat(target)
					if err != nil {
						break
					}
					target = fmt.Sprintf("#{base}-#{n}")
					n++
				}
				f, err := os.Create(target)
				if err != nil {
					configs.Log.Errorf("HTTP-create Cannot create %s: %s\n", target, err)
					continue
				}
				var r io.Reader
				r = bytes.NewBuffer(body)
				if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
					r, err = gzip.NewReader(r)
					if err != nil {
						configs.Log.Errorf("HTTP-gunzip Failed to gzip decode: %s", err)
					}
				}
				if err == nil {
					w, err := io.Copy(f, r)
					if _, ok := r.(*gzip.Reader); ok {
						_ = r.(*gzip.Reader).Close()
					}
					_ = f.Close()
					if err != nil {
						configs.Log.Errorf("HTTP-save %s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
					} else {
						configs.Log.Infof("%s: Saved %s (l:%d)\n", h.ident, target, w)
					}
				}
			}
		}
	}
}

type Request struct {
	*http.Request
}

type RequestBson struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Method      string             `bson:"method"`
	URL         string             `bson:"url"`
	Proto       string             `bson:"proto"`
	Header      http.Header        `bson:"header"`
	Host        string             `bson:"host"`
	RemoteAddr  string             `bson:"remote_addr"`
	RequestURI  string             `bson:"request_uri"`
	ContentType string             `bson:"content_type"`
	UserAgent   string             `bson:"user_agent"`
}

func (r *Request) save() {
	mongo := database.MongoDB
	one, err := mongo.Collection(fmt.Sprintf(ProtocolHttp, time.Now().Format("2006_01_02_15"))).InsertOne(context.TODO(), &RequestBson{
		Method:      r.Method,
		URL:         r.URL.String(),
		Proto:       r.Proto,
		Header:      r.Header,
		Host:        r.Host,
		RemoteAddr:  r.RemoteAddr,
		RequestURI:  r.RequestURI,
		ContentType: r.Header.Get("Content-Type"),
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		configs.Log.Errorf("save protol http2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("save protol http2mongo id:%s", one.InsertedID)
}
