package catalog

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func GetAppByName(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Get username from JWT token
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	//get parameters
	appName := c.Query("app_name")

	page := int64(1) // default value
	if pageStr := c.Query("page"); pageStr != "" {
		if parsedPage, err := strconv.ParseInt(pageStr, 10, 64); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}

	limit := int64(9) // default value
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.ParseInt(limitStr, 10, 64); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	//request on repository
	result, err := repository.GetAppByName(appName, ctx, page, limit, owner)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func GetAllApps(c *gin.Context, repository db.AppRepository) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Get username from JWT token
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var appList []*model.SpecificAppWithoutIDs

	//get limit parameter
	limit := int64(100) // default value
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.ParseInt(limitStr, 10, 64); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	//request on repository
	if result, err := repository.Get(ctx, limit, owner); err != nil {
		logrus.Error(err)
	} else {
		appList = result
	}

	c.JSON(http.StatusOK, gin.H{"apps": &appList})
}
