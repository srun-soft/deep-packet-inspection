package record

import (
	"context"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"github.com/srun-soft/dpi-analysis-toolkit/internal/database"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"time"
)

type Icmp struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Ident       string             `bson:"ident"`
	SrcIP       net.IP             `bson:"src_ip"`
	DstIP       net.IP             `bson:"dst_ip"`
	SrcIPStr    string             `bson:"src_ip_str"`
	DstIPStr    string             `bson:"dst_ip_str"`
	Type        uint8              `bson:"type"`
	Code        uint8              `bson:"code"`
	TTL         uint8              `bson:"ttl"`
	Description string             `bson:"description"`
	Delay       time.Duration      `bson:"delay"`
}

func (i *Icmp) Parse() {

}

func (i *Icmp) Save2Mongo() {
	i.Parse()

	mongo := database.MongoDB.Database(ProtocolICMP)
	one, err := mongo.Collection(time.Now().Format("C_2006_01_02_15")).InsertOne(context.TODO(), i)
	if err != nil {
		configs.Log.Errorf("Save2Mongo protol icmp2mongo err:%s", err)
		return
	}
	configs.Log.Debugf("Save2Mongo protol icmp2mongo id:%s", one.InsertedID)
}
