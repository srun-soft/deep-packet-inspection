package record

import (
	"context"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"net/http"
	"time"
)

// HTTP Protocol

type Http struct {
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

func (h *Http) Parse() {
	h.Domain, h.Suffix = utils.ParseHost(h.Host)
	h.SrcIPStr, h.DstIPStr = h.SrcIP.String(), h.DstIP.String()
}

func (h *Http) Save2Mongo() {
	h.Parse()

	mongo := database.MongoDB.Database(ProtocolHTTP)
	one, err := mongo.Collection(time.Now().Format("C_2006_01_02_15")).InsertOne(context.TODO(), h)
	if err != nil {
		configs.Log.Errorf("Save2Mongo protol http2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("Save2Mongo protol http2mongo id:%s", one.InsertedID)
}
