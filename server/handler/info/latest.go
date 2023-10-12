package info

import (
	db "SAU/mongod"
	"SAU/server/utils"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

func FindLatestVersion(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
	_, err := utils.ValidateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Request on repository
	updateAvailable, linkToLatest, err := repository.CheckLatestVersion(c.Query("app_name"), c.Query("version"), c.Query("channel"), c.Query("platform"), c.Query("arch"), ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"update_available": updateAvailable, "update_url": linkToLatest})
}
