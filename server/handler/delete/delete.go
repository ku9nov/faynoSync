package delete

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func DeleteApp(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//request on repository
	link, result, err := repository.DeleteApp(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}

	index := strings.Index(link, "amazonaws.com/") + len("amazonaws.com/")
	if index > len(link) {
		// The link doesn't contain "amazonaws.com/"
		fmt.Println("Invalid link")
		return
	}
	subLink := link[index:]

	utils.DeleteFromS3(subLink, c, viper.GetViper())
	c.JSON(http.StatusOK, gin.H{"deleteAppResult.DeletedCount": result})
}

func DeleteChannel(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//request on repository
	result, err := repository.DeleteChannel(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"deleteChannelResult.DeletedCount": result})
}

func DeleteArch(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Request on the repository
	result, err := repository.DeleteArch(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"deleteArchResult.DeletedCount": result})
}

func DeletePlatform(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//request on repository
	result, err := repository.DeletePlatform(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"deletePlatformResult.DeletedCount": result})
}
