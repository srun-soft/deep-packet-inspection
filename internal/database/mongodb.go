package database

import (
	"context"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

var (
	MongoDB *mongo.Database
)

func init() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 设置客户端连接配置 TODO 更换配置地址与端口
	opts := options.Client().ApplyURI("mongodb://localhost:27017/dpi")
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		configs.Log.Fatal("Failed to Connect MongoDB!", err)
	}
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			configs.Log.Fatal("Failed to Disconnect MongoDB!", err)
		}
	}()

	// check connect
	if err = client.Ping(ctx, nil); err != nil {
		configs.Log.Fatal("Failed to check connect MongoDB!", err)
	}
	configs.Log.Info("Connected to MongoDB!")
	MongoDB = client.Database("dpi")
}
