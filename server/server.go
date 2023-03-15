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
	handler := handler.NewAppHandler(client, db)

	// Add authentication middleware to required paths
	mongoDatabase := client.Database(configDB.Database)

	authMiddleware := utils.AuthMiddleware(mongoDatabase)

	router.GET("/health", handler.HealthCheck)
	router.POST("/checkVersion", handler.FindLatestVersion)
	router.POST("/login", handler.Login)

	router.Use(authMiddleware)

	router.GET("/", handler.GetAllApps)
	router.POST("/upload", handler.UploadApp)
	router.GET("/search", handler.GetAppByName)
	router.DELETE("/delete", handler.DeleteApp)

	// get the port from the configuration file
	port := config.GetString("PORT")
	if port == "" {
		port = "9000"
	}
	router.Run(":" + port)
}
