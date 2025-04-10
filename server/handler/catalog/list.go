package catalog

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func ListChannels(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var channelsList []*model.Channel

	//request on repository
	if result, err := repository.ListChannels(ctx, owner); err != nil {
		logrus.Error(err)
	} else {
		channelsList = result
	}

	c.JSON(http.StatusOK, gin.H{"channels": &channelsList})
}

func ListPlatforms(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var platformsList []*model.Platform

	//request on repository
	if result, err := repository.ListPlatforms(ctx, owner); err != nil {
		logrus.Error(err)
	} else {
		platformsList = result
	}

	c.JSON(http.StatusOK, gin.H{"platforms": &platformsList})
}

func ListArchs(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var archsList []*model.Arch

	//request on repository
	if result, err := repository.ListArchs(ctx, owner); err != nil {
		logrus.Error(err)
	} else {
		archsList = result
	}

	c.JSON(http.StatusOK, gin.H{"archs": &archsList})
}

func ListApps(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var appsList []*model.App

	//request on repository
	if result, err := repository.ListApps(ctx, owner); err != nil {
		logrus.Error(err)
	} else {
		appsList = result
	}

	c.JSON(http.StatusOK, gin.H{"apps": &appsList})
}
