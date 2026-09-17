package download

import (
	"context"
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func ListDownloadTokens(c *gin.Context, repository db.AppRepository) {
	requester, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	downloadTokens, err := repository.ListDownloadTokens(requester, ctx)
	if err != nil {
		logrus.Errorf("Failed to list download tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"download_tokens": downloadTokens})
}

func RegenerateDownloadToken(c *gin.Context, repository db.AppRepository) {
	var req model.RegenerateDownloadTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	requester, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	appID, err := primitive.ObjectIDFromHex(req.AppID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app ID format"})
		return
	}

	channelID := primitive.NilObjectID
	if req.ChannelID != "" {
		channelID, err = primitive.ObjectIDFromHex(req.ChannelID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid channel ID format"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	token, err := repository.RegenerateDownloadToken(appID, channelID, requester, ctx)
	if err != nil {
		logrus.Errorf("Failed to regenerate download token for app %s: %v", req.AppID, err)
		switch {
		case errors.Is(err, db.ErrAppNotFound), errors.Is(err, db.ErrChannelNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case errors.Is(err, db.ErrDownloadTokenPublicApp):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"app_id":     req.AppID,
		"channel_id": req.ChannelID,
		"token":      token,
	})
}
