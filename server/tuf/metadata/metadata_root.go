package metadata

import (
	"context"
	"errors"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func GetMetadataRoot(c *gin.Context) {
	getTrustedMetadata(c, "trusted_root", func(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
		return loadTrustedRootFromS3(ctx, adminName, appName)
	})
}

func GetMetadataTargets(c *gin.Context) {
	getTrustedMetadata(c, "trusted_targets", func(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
		return loadTrustedTargetsFromS3(ctx, adminName, appName)
	})
}

func GetMetadataDelegated(c *gin.Context) {
	getTrustedMetadata(c, "trusted_delegated", func(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
		roleName := c.Query("roleName")
		if roleName == "" {
			return nil, errRoleNameRequired
		}
		return loadTrustedDelegatedFromS3(ctx, adminName, appName, roleName)
	})
}

var errRoleNameRequired = errors.New("roleName query parameter is required")

func getTrustedMetadata(
	c *gin.Context,
	responseKey string,
	loader func(ctx context.Context, adminName string, appName string) (map[string]interface{}, error),
) {
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
	if err := tuf_utils.ValidateAppName(appName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := context.Background()
	trustedMetadata, err := loader(ctx, adminName, appName)
	if err == errRoleNameRequired {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "roleName query parameter is required",
		})
		return
	}
	if err == nil && trustedMetadata != nil {
		logrus.Debugf("Added %s to response", responseKey)
	} else {
		logrus.Debugf("Could not load %s: %v", responseKey, err)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			responseKey: trustedMetadata,
		},
	})
}
