package metadata

import (
	"context"
	"faynoSync/server/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func GetMetadataRoot(c *gin.Context) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	appName := c.Query("appName")
	if appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appName query parameter is required",
		})
		return
	}
	ctx := context.Background()
	trustedRoot, err := loadTrustedRootFromS3(ctx, adminName, appName)
	if err == nil && trustedRoot != nil {
		logrus.Debug("Added trusted_root to response")
	} else {
		logrus.Debugf("Could not load trusted_root: %v", err)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"trusted_root": trustedRoot,
		},
	})
}
