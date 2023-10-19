package create

import (
	db "SAU/mongod"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func CreateChannel(c *gin.Context, repository db.AppRepository) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := repository.CreateChannel(c.Query("channel"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload channel data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createChannelResult.Created": result})
}

func CreatePlatform(c *gin.Context, repository db.AppRepository) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := repository.CreatePlatform(c.Query("platform"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload platform data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createPlatformResult.Created": result})
}

func CreateArch(c *gin.Context, repository db.AppRepository) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := repository.CreateArch(c.Query("arch"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload arch data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createArchResult.Created": result})
}

func CreatePackage(c *gin.Context, repository db.AppRepository) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := repository.CreatePackage(c.Query("package"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload package data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createPackageResult.Created": result})
}
