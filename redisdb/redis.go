package redisdb

import (
	"context"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

var client *redis.Client

func ConnectToRedis(config RedisConfig) *redis.Client {
	if client != nil {
		return client
	}

	options := &redis.Options{
		Addr:     config.Addr,
		Password: config.Password,
		DB:       config.DB,
	}

	client = redis.NewClient(options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Ping(ctx).Result()
	if err != nil {
		logrus.Errorln("Failed to connect to Redis:", err)
		os.Exit(1)
	}

	logrus.Infoln("Connected to Redis successfully")
	return client
}
