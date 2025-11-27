package tuf

import (
	"faynoSync/server/tuf/bootstrap"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetupRoutes(router *gin.Engine, authMiddleware gin.HandlerFunc, mongoDatabase *mongo.Database, redisClient *redis.Client) {
	adminMiddleware := utils.AdminOnlyMiddleware(mongoDatabase)

	router.GET("/tuf/v1/bootstrap", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.GetBootstrapStatus(c, redisClient)
	})
	router.POST("/tuf/v1/bootstrap", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.PostBootstrap(c, redisClient, mongoDatabase)
	})
	router.GET("/tuf/v1/bootstrap/locks", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.GetBootstrapLocks(c, redisClient)
	})
	router.POST("/tuf/v1/bootstrap/generate", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.GenerateRootKeys(c, mongoDatabase)
	})
}
