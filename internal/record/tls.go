package record

import (
	"context"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"time"
)

// Handshake Protocol
// Client Hello Analyze

type Tls struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Host       string             `bson:"host"`
	Domain     string             `bson:"domain"`
	Suffix     string             `bson:"suffix"`
	SrcIP      net.IP             `bson:"src_ip"`
	DstIP      net.IP             `bson:"dst_ip"`
	SrcIPStr   string             `bson:"src_ip_str"`
	DstIPStr   string             `bson:"dst_ip_str"`
	Ident      string             `bson:"ident"`
	UpStream   int                `bson:"up_stream"`
	DownStream int                `bson:"down_stream"`
	StartTime  time.Time          `bson:"start_time"`
	EndTime    time.Time          `bson:"end_time"`
}

func (h *Tls) Parse() {
	h.Domain, h.Suffix = utils.ParseHost(h.Host)
	h.SrcIPStr, h.DstIPStr = h.SrcIP.String(), h.DstIP.String()
}

func (h *Tls) Save2Mongo() {
	h.Parse()
	mongo := database.MongoDB.Database(ProtocolHTTPS)
	one, err := mongo.Collection(time.Now().Format("C_2006_01_02_15")).InsertOne(context.TODO(), h)
	if err != nil {
		configs.Log.Errorf("Save2Mongo protocol handshake2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("Save2Mongo protocol handshake2mongo id:%s", one)
}
