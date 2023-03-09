package server

import (
	db "SAU/mongod"
	"SAU/server/handler"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func StartServer(config *viper.Viper, migration, rollback bool) {
	mongoUrl := config.GetString("MONGODB_URL")
	switch {
	case migration && rollback:
		db.ConnectToDatabase(mongoUrl, true, false)
	case migration && !rollback:
		db.ConnectToDatabase(mongoUrl, true, true)
	default:
		db.ConnectToDatabase(mongoUrl, false, false)
	}

	router := gin.Default()

	client, configDB := db.ConnectToDatabase(mongoUrl, false, false)

	db := db.NewAppRepository(&configDB, client)
	handler := handler.NewAppHandler(client, db)
	router.GET("/health", handler.HealthCheck)
	router.GET("/", handler.GetAllApps)
	router.POST("/upload", handler.UploadApp)
	router.GET("/search", handler.GetAppByName)
	router.DELETE("/delete", handler.DeleteApp)
	router.POST("/checkVersion", handler.FindLatestVersion)

	// get the port from the configuration file
	port := config.GetString("PORT")
	if port == "" {
		port = "9000"
	}
	router.Run(":" + port)
}
