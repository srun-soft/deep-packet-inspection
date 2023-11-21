package packet_capture

import (
	"context"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"time"
)

// DNS analyze

type DNSBson struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	SrcIP    net.IP             `bson:"src_ip"`
	DstIP    net.IP             `bson:"dst_ip"`
	SrcIPStr string             `bson:"src_ip_str"`
	DstIPStr string             `bson:"dst_ip_str"`
	Host     string             `bson:"host"`
	Domain   string             `bson:"domain"`
	Suffix   string             `bson:"suffix"`
	Type     string             `bson:"type"`
	Class    string             `bson:"class"`
}

func (d *DNSBson) Parse() {
	d.Domain, d.Suffix = utils.Parse(d.Host)
}

func (d *DNSBson) Save2Mongo() {
	d.Parse()

	mongo := database.MongoDB.Database(ProtocolDNS)
	one, err := mongo.Collection(time.Now().Format("C_2006_01_02_15")).InsertOne(context.TODO(), d)
	if err != nil {
		configs.Log.Errorf("Save2Mongo protocol dns2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("Save2Mongo protocol dns2mongo id:%s", one)
}
