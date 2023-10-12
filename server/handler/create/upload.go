package create

import (
	db "SAU/mongod"
	"SAU/server/utils"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

func UploadApp(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
	ctxQueryMap, err := utils.ValidateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get file from form data
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "file is required",
		})
		return
	}

	link := utils.UploadToS3(ctxQueryMap, file, c, viper.GetViper())

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := repository.Upload(ctxQueryMap, link, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": result})
}
