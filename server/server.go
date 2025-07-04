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

	// Initialize Redis client
	var redisClient *redis.Client

	if config.GetBool("PERFORMANCE_MODE") || config.GetBool("ENABLE_TELEMETRY") {
		logrus.Infoln("Redis connection is required. Connecting to Redis.")
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

	router.GET("/checkVersion", handler.FindLatestVersion)
	router.GET("/apps/latest", handler.FetchLatestVersionOfApp)
	router.POST("/signup", handler.SignUp)
	router.POST("/login", handler.Login)

	if config.GetBool("ENABLE_PRIVATE_APP_DOWNLOADING") {
		router.GET("/download", handler.DownloadArtifact)
		router.Use(authMiddleware)
	} else {
		router.Use(authMiddleware)
		router.GET("/download", utils.CheckPermission(utils.PermissionDownload, utils.ResourceApps, mongoDatabase), handler.DownloadArtifact)
	}

	// App routes
	// router.GET("/", handler.GetAllApps)
	router.GET("/whoami", handler.Whoami)
	router.POST("/upload", utils.CheckPermission(utils.PermissionUpload, utils.ResourceApps, mongoDatabase), handler.UploadApp)
	router.POST("/apps/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), handler.UpdateSpecificApp)
	router.POST("/app/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), handler.UpdateApp)
	router.DELETE("/apps/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps, mongoDatabase), handler.DeleteSpecificVersionOfApp)
	router.GET("/search", handler.GetAppByName)

	// Channel routes
	router.POST("/channel/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceChannels, mongoDatabase), handler.CreateChannel)
	router.GET("/channel/list", handler.ListChannels)
	router.DELETE("/channel/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceChannels, mongoDatabase), handler.DeleteChannel)
	router.POST("/channel/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceChannels, mongoDatabase), handler.UpdateChannel)

	// Platform routes
	router.POST("/platform/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourcePlatforms, mongoDatabase), handler.CreatePlatform)
	router.GET("/platform/list", handler.ListPlatforms)
	router.DELETE("/platform/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourcePlatforms, mongoDatabase), handler.DeletePlatform)
	router.POST("/platform/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourcePlatforms, mongoDatabase), handler.UpdatePlatform)

	// Arch routes
	router.POST("/arch/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceArchs, mongoDatabase), handler.CreateArch)
	router.GET("/arch/list", handler.ListArchs)
	router.DELETE("/arch/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceArchs, mongoDatabase), handler.DeleteArch)
	router.POST("/arch/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceArchs, mongoDatabase), handler.UpdateArch)

	// App management routes
	router.POST("/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, mongoDatabase), handler.CreateApp)
	router.GET("/app/list", handler.ListApps)
	router.DELETE("/app/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps, mongoDatabase), handler.DeleteApp)
	router.POST("/artifact/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps, mongoDatabase), handler.DeleteSpecificArtifactOfApp)

	// Team user management - only admins can create team users
	router.POST("/user/create", authMiddleware, utils.AdminOnlyMiddleware(mongoDatabase), handler.CreateTeamUser)
	router.POST("/user/update", authMiddleware, utils.AdminOnlyMiddleware(mongoDatabase), handler.UpdateTeamUser)
	router.GET("/users/list", authMiddleware, utils.AdminOnlyMiddleware(mongoDatabase), handler.ListTeamUsers)
	router.DELETE("/user/delete", authMiddleware, utils.AdminOnlyMiddleware(mongoDatabase), handler.DeleteTeamUser)
	router.POST("/admin/update", authMiddleware, utils.AdminOnlyMiddleware(mongoDatabase), handler.UpdateAdmin)

	// Telemetry endpoint
	router.GET("/telemetry", authMiddleware, telemetryMiddleware(config), handler.GetTelemetry)

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

func telemetryMiddleware(config *viper.Viper) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.GetBool("ENABLE_TELEMETRY") {
			c.JSON(403, gin.H{
				"error": "Telemetry is not enabled on this instance",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
