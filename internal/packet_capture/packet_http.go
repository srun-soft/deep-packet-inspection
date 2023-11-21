package packet_capture

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"net"
	"net/http"
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
			httpBson := &HTTPBson{
				Ident:       h.ident,
				SrcIP:       h.parent.src,
				DstIP:       h.parent.dst,
				Method:      req.Method,
				URL:         req.URL.String(),
				Proto:       req.Proto,
				Header:      req.Header,
				Host:        req.Host,
				RemoteAddr:  req.RemoteAddr,
				RequestURI:  req.RequestURI,
				ContentType: req.Header.Get("Content-Type"),
				UserAgent:   req.UserAgent(),
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

type HTTPBson struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Ident       string             `bson:"ident"`
	SrcIP       net.IP             `bson:"src_ip"`
	DstIP       net.IP             `bson:"dst_ip"`
	SrcIPStr    string             `bson:"src_ip_str"`
	DstIPStr    string             `bson:"dst_ip_str"`
	Method      string             `bson:"method"`
	URL         string             `bson:"url"`
	Proto       string             `bson:"proto"`
	Header      http.Header        `bson:"header"`
	Host        string             `bson:"host"`
	Domain      string             `bson:"domain"`
	Suffix      string             `bson:"suffix"`
	RemoteAddr  string             `bson:"remote_addr"`
	RequestURI  string             `bson:"request_uri"`
	ContentType string             `bson:"content_type"`
	UserAgent   string             `bson:"user_agent"`
}

func (h *HTTPBson) Parse() {
	h.Domain, h.Suffix = utils.Parse(h.Host)
	h.SrcIPStr, h.DstIPStr = h.SrcIP.String(), h.DstIP.String()
}

func (h *HTTPBson) Save2Mongo() {
	h.Parse()
	mongo := database.MongoDB.Database(ProtocolHTTP)
	one, err := mongo.Collection(time.Now().Format("C_2006_01_02_15")).InsertOne(context.TODO(), h)
	if err != nil {
		configs.Log.Errorf("Save2Mongo protol http2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("Save2Mongo protol http2mongo id:%s", one.InsertedID)
}
