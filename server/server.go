package server

import (
	db "faynoSync/mongod"
	"faynoSync/redisdb"
	"faynoSync/server/handler"
	"faynoSync/server/utils"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func StartServer(config *viper.Viper, flags map[string]interface{}) {
	mongoUrl := config.GetString("MONGODB_URL")

	router := gin.Default()

	client, configDB := db.ConnectToDatabase(mongoUrl, flags)

	db := db.NewAppRepository(&configDB, client)

	mongoDatabase := client.Database(configDB.Database)

	// Check PERFORMANCE_MODE
	var redisClient *redis.Client

	if config.GetBool("PERFORMANCE_MODE") {
		logrus.Infoln(("Perfomance mod is enabled. Connecting to Redis."))
		redisConfig := redisdb.RedisConfig{
			Addr:     config.GetString("REDIS_HOST") + ":" + config.GetString("REDIS_PORT"),
			Password: config.GetString("REDIS_PASSWORD"),
			DB:       config.GetInt("REDIS_DB"),
		}
		redisClient = redisdb.ConnectToRedis(redisConfig)
	}
	handler := handler.NewAppHandler(client, db, mongoDatabase, redisClient, config.GetBool("PERFORMANCE_MODE"))
	os.Setenv("API_KEY", config.GetString("API_KEY"))
	os.Setenv("ENABLE_PRIVATE_APP_DOWNLOADING", config.GetString("ENABLE_PRIVATE_APP_DOWNLOADING"))
	// Add authentication middleware to required paths
	authMiddleware := utils.AuthMiddleware()

	router.GET("/health", handler.HealthCheck)

	allowedCORS := config.GetString("ALLOWED_CORS")
	allowedOrigins := strings.Split(allowedCORS, ",")

	router.Use(corsMiddleware(allowedOrigins))

	// Add database to context
	router.Use(func(c *gin.Context) {
		c.Set("database", mongoDatabase)
		c.Next()
	})

	router.GET("/checkVersion", handler.FindLatestVersion)
	router.GET("/apps/latest", handler.FetchLatestVersionOfApp)
	router.POST("/signup", handler.SignUp)
	router.POST("/login", handler.Login)

	// Team user management - only admins can create team users
	router.POST("/user/create", authMiddleware, utils.AdminOnlyMiddleware(), handler.CreateTeamUser)

	if config.GetBool("ENABLE_PRIVATE_APP_DOWNLOADING") {
		router.GET("/download", handler.DownloadArtifact)
		router.Use(authMiddleware)
	} else {
		router.Use(authMiddleware)
		router.GET("/download", handler.DownloadArtifact)
	}

	// App routes
	router.GET("/", handler.GetAllApps)
	router.POST("/upload", utils.CheckPermission(utils.PermissionUpload, utils.ResourceApps), handler.UploadApp)
	router.POST("/apps/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps), handler.UpdateSpecificApp)
	router.POST("/app/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps), handler.UpdateApp)
	router.DELETE("/apps/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps), handler.DeleteSpecificVersionOfApp)
	router.GET("/search", handler.GetAppByName)

	// Channel routes
	router.POST("/channel/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceChannels), handler.CreateChannel)
	router.GET("/channel/list", handler.ListChannels)
	router.DELETE("/channel/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceChannels), handler.DeleteChannel)
	router.POST("/channel/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceChannels), handler.UpdateChannel)

	// Platform routes
	router.POST("/platform/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourcePlatforms), handler.CreatePlatform)
	router.GET("/platform/list", handler.ListPlatforms)
	router.DELETE("/platform/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourcePlatforms), handler.DeletePlatform)
	router.POST("/platform/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourcePlatforms), handler.UpdatePlatform)

	// Arch routes
	router.POST("/arch/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceArchs), handler.CreateArch)
	router.GET("/arch/list", handler.ListArchs)
	router.DELETE("/arch/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceArchs), handler.DeleteArch)
	router.POST("/arch/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceArchs), handler.UpdateArch)

	// App management routes
	router.POST("/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps), handler.CreateApp)
	router.GET("/app/list", handler.ListApps)
	router.DELETE("/app/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps), handler.DeleteApp)
	router.POST("/artifact/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps), handler.DeleteSpecificArtifactOfApp)

	// get the port from the configuration file
	port := config.GetString("PORT")
	if port == "" {
		port = "9000"
	}
	router.Run(":" + port)
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
