package packet_capture

import (
	"context"
	"fmt"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"time"
)

// DNS analyze

type DnsBson struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	SrcIP    net.IP             `bson:"src_ip"`
	DstIP    net.IP             `bson:"dst_ip"`
	SrcIPStr string             `bson:"src_ip_str"`
	DstIPStr string             `bson:"dst_ip_str"`
	Name     string             `bson:"name"`
	Type     string             `bson:"type"`
	Class    string             `bson:"class"`
}

func (d *DnsBson) save() {
	mongo := database.MongoDB
	one, err := mongo.Collection(fmt.Sprintf(ProtocolDNS, time.Now().Format("2006_01_02_15"))).InsertOne(context.TODO(), d)
	if err != nil {
		configs.Log.Errorf("save protocol dns2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("save protocol dns2mongo id:%s", one)
}
