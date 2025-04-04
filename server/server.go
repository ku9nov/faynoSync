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
	router.GET("/download", handler.DownloadArtifact)

	router.Use(authMiddleware)

	router.GET("/", handler.GetAllApps)
	router.POST("/upload", handler.UploadApp)
	router.POST("/apps/update", handler.UpdateSpecificApp)
	router.POST("/app/update", handler.UpdateApp)
	router.POST("/channel/update", handler.UpdateChannel)
	router.POST("/platform/update", handler.UpdatePlatform)
	router.POST("/arch/update", handler.UpdateArch)
	router.GET("/search", handler.GetAppByName)
	router.DELETE("/apps/delete", handler.DeleteSpecificVersionOfApp)
	router.POST("/channel/create", handler.CreateChannel)
	router.GET("/channel/list", handler.ListChannels)
	router.DELETE("/channel/delete", handler.DeleteChannel)
	router.POST("/platform/create", handler.CreatePlatform)
	router.GET("/platform/list", handler.ListPlatforms)
	router.DELETE("/platform/delete", handler.DeletePlatform)
	router.POST("/arch/create", handler.CreateArch)
	router.GET("/arch/list", handler.ListArchs)
	router.DELETE("/arch/delete", handler.DeleteArch)
	router.POST("/app/create", handler.CreateApp)
	router.GET("/app/list", handler.ListApps)
	router.DELETE("/app/delete", handler.DeleteApp)
	router.POST("/artifact/delete", handler.DeleteSpecificArtifactOfApp)
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
