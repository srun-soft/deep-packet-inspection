package database

import (
	"context"
	"github.com/redis/go-redis/v9"
	"github.com/srun-soft/dpi-analysis-toolkit/configs"
	"time"
)

var (
	Rdb *redis.Client
)

func init() {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	rdb := redis.NewClient(&redis.Options{
		// TODO 具体的redis连接配置
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		configs.Log.Fatalln("Failed to connection Redis", err)
	}
	configs.Log.Info("Connected to Redis!")
	Rdb = rdb
}
