package info

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

func HealthCheck(c *gin.Context, mongoClient *mongo.Client, redisClient *redis.Client, performanceMode bool) {
	ctx, ctxCancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer ctxCancel()

	if err := mongoClient.Ping(ctx, nil); err != nil {
		logrus.Error("MongoDB connection error: ", err)
		c.JSON(http.StatusFailedDependency, gin.H{"status": "unhealthy", "details": "MongoDB connection failed"})
		return
	}

	if performanceMode {
		if err := redisClient.Ping(ctx).Err(); err != nil {
			logrus.Error("Redis connection error: ", err)
			c.JSON(http.StatusFailedDependency, gin.H{"status": "unhealthy", "details": "Redis connection failed"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}
