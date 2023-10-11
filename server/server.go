package server

import (
	db "SAU/mongod"
	"SAU/server/handler"
	"SAU/server/utils"

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

	// Add authentication middleware to required paths
	authMiddleware := utils.AuthMiddleware(mongoDatabase)

	router.GET("/health", handler.HealthCheck)
	router.POST("/checkVersion", handler.FindLatestVersion)
	router.POST("/login", handler.Login)

	router.Use(authMiddleware)

	router.GET("/", handler.GetAllApps)
	router.POST("/upload", handler.UploadApp)
	router.GET("/search", handler.GetAppByName)
	router.DELETE("/deleteApp", handler.DeleteApp)
	router.POST("/createChannel", handler.CreateChannel)
	router.GET("/listChannels", handler.ListChannels)
	router.DELETE("/deleteChannel", handler.DeleteChannel)
	router.POST("/createPlatform", handler.CreatePlatform)
	router.GET("/listPlatforms", handler.ListPlatforms)
	router.DELETE("/deletePlatform", handler.DeletePlatform)
	router.POST("/createArch", handler.CreateArch)
	router.GET("/listArchs", handler.ListArchs)
	router.DELETE("/deleteArch", handler.DeleteArch)
	// get the port from the configuration file
	port := config.GetString("PORT")
	if port == "" {
		port = "9000"
	}
	router.Run(":" + port)
}
