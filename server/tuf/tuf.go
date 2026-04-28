package tuf

import (
	"faynoSync/mongod"
	"faynoSync/server/tuf/artifacts"
	"faynoSync/server/tuf/bootstrap"
	"faynoSync/server/tuf/config"
	"faynoSync/server/tuf/metadata"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetupRoutes(router *gin.Engine, authMiddleware gin.HandlerFunc, mongoDatabase *mongo.Database, redisClient *redis.Client, appRepository mongod.AppRepository) {
	adminMiddleware := utils.AdminOnlyMiddleware(mongoDatabase)
	appEditPermissionMiddleware := utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase)
	resolveOwnerMiddleware := utils.ResolveOwnerMiddleware(mongoDatabase)

	router.GET("/tuf/v1/bootstrap", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.GetBootstrapStatus(c, redisClient)
	})
	router.POST("/tuf/v1/bootstrap", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.PostBootstrap(c, redisClient)
	})
	router.POST("/tuf/v1/bootstrap/recovery", authMiddleware, adminMiddleware, func(c *gin.Context) {
		bootstrap.PostBootstrapRecovery(c, redisClient)
	})
	router.GET("/tuf/v1/task", authMiddleware, appEditPermissionMiddleware, resolveOwnerMiddleware, func(c *gin.Context) {
		tasks.GetTask(c, redisClient)
	})
	router.POST("/tuf/v1/artifacts/publish", authMiddleware, appEditPermissionMiddleware, resolveOwnerMiddleware, func(c *gin.Context) {
		artifacts.PostPublishArtifacts(c, redisClient, mongoDatabase)
	})
	router.POST("/tuf/v1/artifacts/delete", authMiddleware, appEditPermissionMiddleware, resolveOwnerMiddleware, func(c *gin.Context) {
		artifacts.PostDeleteArtifacts(c, redisClient, mongoDatabase)
	})
	router.GET("/tuf/v1/config", authMiddleware, adminMiddleware, func(c *gin.Context) {
		config.GetConfig(c, redisClient)
	})
	router.PUT("/tuf/v1/config", authMiddleware, adminMiddleware, func(c *gin.Context) {
		config.PutConfig(c, redisClient)
	})
	router.POST("/tuf/v1/metadata", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.PostMetadataRotate(c, redisClient)
	})
	router.POST("/tuf/v1/metadata/rotate-keys", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.PostMetadataRotateKeys(c, redisClient)
	})
	router.GET("/tuf/v1/metadata/sign", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.GetMetadataSign(c, redisClient)
	})
	router.POST("/tuf/v1/metadata/sign", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.PostMetadataSign(c, redisClient)
	})
	router.POST("/tuf/v1/metadata/sign/delete", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.PostMetadataSignDelete(c, redisClient)
	})
	router.POST("/tuf/v1/metadata/online", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.PostMetadataOnline(c, redisClient)
	})
	router.GET("/tuf/v1/metadata/root", authMiddleware, adminMiddleware, func(c *gin.Context) {
		metadata.GetMetadataRoot(c)
	})
}
