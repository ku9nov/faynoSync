package report

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func RegenerateReportKey(c *gin.Context, repository db.AppRepository) {
	var req model.RegenerateReportKeyRequest
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	newKeyValue, err := repository.RegenerateReportKey(appID, requester, ctx)
	if err != nil {
		logrus.Errorf("Failed to regenerate report key for app %s: %v", req.AppID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"app_id":    req.AppID,
		"key_value": newKeyValue,
	})
}
