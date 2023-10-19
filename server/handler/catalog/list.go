package catalog

import (
	db "SAU/mongod"
	"SAU/server/model"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func ListChannels(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var channelsList []*model.Channel

	//request on repository
	if result, err := repository.ListChannels(ctx); err != nil {
		logrus.Error(err)
	} else {
		channelsList = result
	}

	c.JSON(http.StatusOK, gin.H{"channels": &channelsList})
}

func ListPlatforms(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var platformsList []*model.Platform

	//request on repository
	if result, err := repository.ListPlatforms(ctx); err != nil {
		logrus.Error(err)
	} else {
		platformsList = result
	}

	c.JSON(http.StatusOK, gin.H{"platforms": &platformsList})
}

func ListArchs(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var archsList []*model.Arch

	//request on repository
	if result, err := repository.ListArchs(ctx); err != nil {
		logrus.Error(err)
	} else {
		archsList = result
	}

	c.JSON(http.StatusOK, gin.H{"archs": &archsList})
}

func ListPackages(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var packageTypesList []*model.Package

	//request on repository
	if result, err := repository.ListPackages(ctx); err != nil {
		logrus.Error(err)
	} else {
		packageTypesList = result
	}

	c.JSON(http.StatusOK, gin.H{"packages": &packageTypesList})
}
