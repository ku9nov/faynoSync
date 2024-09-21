package server

import (
	db "faynoSync/mongod"
	"faynoSync/server/handler"
	"faynoSync/server/utils"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func StartServer(config *viper.Viper, flags map[string]interface{}) {
	mongoUrl := config.GetString("MONGODB_URL")

	router := gin.Default()

	client, configDB := db.ConnectToDatabase(mongoUrl, flags)

	db := db.NewAppRepository(&configDB, client)

	mongoDatabase := client.Database(configDB.Database)

	handler := handler.NewAppHandler(client, db, mongoDatabase)
	os.Setenv("API_KEY", config.GetString("API_KEY"))

	// Add authentication middleware to required paths
	authMiddleware := utils.AuthMiddleware()

	router.GET("/health", handler.HealthCheck)

	allowedCORS := config.GetString("ALLOWED_CORS")
	allowedOrigins := strings.Split(allowedCORS, ",")

	router.Use(corsMiddleware(allowedOrigins))
	router.GET("/checkVersion", handler.FindLatestVersion)
	router.POST("/signup", handler.SignUp)
	router.POST("/login", handler.Login)

	router.Use(authMiddleware)

	router.GET("/", handler.GetAllApps)
	router.POST("/upload", handler.UploadApp)
	router.POST("/apps/update", handler.UpdateSpecificApp)
	router.POST("/updateApp", handler.UpdateApp)
	router.POST("/updateChannel", handler.UpdateChannel)
	router.POST("/updatePlatform", handler.UpdatePlatform)
	router.POST("/updateArch", handler.UpdateArch)
	router.GET("/search", handler.GetAppByName)
	router.DELETE("/apps/delete", handler.DeleteSpecificVersionOfApp)
	router.POST("/createChannel", handler.CreateChannel)
	router.GET("/listChannels", handler.ListChannels)
	router.DELETE("/deleteChannel", handler.DeleteChannel)
	router.POST("/createPlatform", handler.CreatePlatform)
	router.GET("/listPlatforms", handler.ListPlatforms)
	router.DELETE("/deletePlatform", handler.DeletePlatform)
	router.POST("/createArch", handler.CreateArch)
	router.GET("/listArchs", handler.ListArchs)
	router.DELETE("/deleteArch", handler.DeleteArch)
	router.POST("/createApp", handler.CreateApp)
	router.GET("/listApps", handler.ListApps)
	router.DELETE("/deleteApp", handler.DeleteApp)

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
