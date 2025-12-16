package tuf

import (
	"faynoSync/mongod"
	"faynoSync/server/tuf/artifacts"
	"faynoSync/server/tuf/bootstrap"
	"faynoSync/server/tuf/config"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetupRoutes(router *gin.Engine, authMiddleware gin.HandlerFunc, mongoDatabase *mongo.Database, redisClient *redis.Client, appRepository mongod.AppRepository) {
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
		bootstrap.GenerateRootKeys(c, mongoDatabase, redisClient, appRepository)
	})
	router.GET("/tuf/v1/task", authMiddleware, adminMiddleware, func(c *gin.Context) {
		tasks.GetTask(c, redisClient)
	})
	router.POST("/tuf/v1/artifacts/publish", authMiddleware, adminMiddleware, func(c *gin.Context) {
		artifacts.PostPublishArtifacts(c, redisClient, mongoDatabase)
	})
	router.POST("/tuf/v1/artifacts/delete", authMiddleware, adminMiddleware, func(c *gin.Context) {
		artifacts.PostDeleteArtifacts(c, redisClient, mongoDatabase)
	})
	router.GET("/tuf/v1/config", authMiddleware, adminMiddleware, func(c *gin.Context) {
		config.GetConfig(c, redisClient)
	})
	router.PUT("/tuf/v1/config", authMiddleware, adminMiddleware, func(c *gin.Context) {
		config.PutConfig(c, redisClient)
	})
}
