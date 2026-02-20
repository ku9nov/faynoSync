package utils

import (
	"context"
	"faynoSync/server/model"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type PermissionType string

const (
	PermissionCreate   PermissionType = "create"
	PermissionDelete   PermissionType = "delete"
	PermissionEdit     PermissionType = "edit"
	PermissionDownload PermissionType = "download"
	PermissionUpload   PermissionType = "upload"
)

type ResourceType string

const (
	ResourceApps      ResourceType = "apps"
	ResourceChannels  ResourceType = "channels"
	ResourcePlatforms ResourceType = "platforms"
	ResourceArchs     ResourceType = "archs"
)

// CheckPermission creates a middleware that checks if the user has the required permission
// This function should be called with the database connection
func CheckPermission(permissionType PermissionType, resourceType ResourceType, database *mongo.Database) gin.HandlerFunc {
	logrus.Debugf("CheckPermission: permissionType: %v, resourceType: %v", permissionType, resourceType)
	return func(c *gin.Context) {
		username, err := GetUsernameFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if isAPIToken, exists := c.Get("is_api_token"); exists {
			logrus.Debugf("is_api_token: %v, permissionType: %v, resourceType: %v", isAPIToken, permissionType, resourceType)
			if apiTokenValue, ok := isAPIToken.(bool); ok && apiTokenValue {
				if permissionType != PermissionUpload || resourceType != ResourceApps {
					c.JSON(http.StatusForbidden, gin.H{"error": "API tokens are restricted to app upload"})
					c.Abort()
					return
				}

				allowedAppsRaw, ok := c.Get("allowed_apps")
				if !ok {
					c.JSON(http.StatusForbidden, gin.H{"error": "API token scope is missing"})
					c.Abort()
					return
				}

				allowedApps, ok := allowedAppsRaw.([]string)
				if !ok || len(allowedApps) == 0 {
					c.JSON(http.StatusForbidden, gin.H{"error": "API token has no allowed applications"})
					c.Abort()
					return
				}

				c.Set("allowed_apps", allowedApps)
				c.Next()
				return
			}
		}

		// First check if user is an admin
		adminsCollection := database.Collection("admins")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()

		var adminUser bson.M
		err = adminsCollection.FindOne(ctx, bson.M{"username": username}).Decode(&adminUser)
		if err == nil {
			// User is an admin, allow access
			c.Next()
			return
		}

		// If not admin, check team user permissions
		teamUsersCollection := database.Collection("team_users")
		var teamUser model.TeamUser
		err = teamUsersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&teamUser)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		// Check if user has the required permission
		var hasPermission bool
		switch resourceType {
		case ResourceApps:
			switch permissionType {
			case PermissionCreate:
				hasPermission = teamUser.Permissions.Apps.Create
			case PermissionDelete:
				hasPermission = teamUser.Permissions.Apps.Delete
			case PermissionEdit:
				hasPermission = teamUser.Permissions.Apps.Edit
			case PermissionDownload:
				hasPermission = teamUser.Permissions.Apps.Download
			case PermissionUpload:
				hasPermission = teamUser.Permissions.Apps.Upload
			}
		case ResourceChannels:
			switch permissionType {
			case PermissionCreate:
				hasPermission = teamUser.Permissions.Channels.Create
			case PermissionDelete:
				hasPermission = teamUser.Permissions.Channels.Delete
			case PermissionEdit:
				hasPermission = teamUser.Permissions.Channels.Edit
			}
		case ResourcePlatforms:
			switch permissionType {
			case PermissionCreate:
				hasPermission = teamUser.Permissions.Platforms.Create
			case PermissionDelete:
				hasPermission = teamUser.Permissions.Platforms.Delete
			case PermissionEdit:
				hasPermission = teamUser.Permissions.Platforms.Edit
			}
		case ResourceArchs:
			switch permissionType {
			case PermissionCreate:
				hasPermission = teamUser.Permissions.Archs.Create
			case PermissionDelete:
				hasPermission = teamUser.Permissions.Archs.Delete
			case PermissionEdit:
				hasPermission = teamUser.Permissions.Archs.Edit
			}
		}

		if !hasPermission {
			logrus.Errorf("Permission denied for user %s: %s %s", username, resourceType, permissionType)
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}

		// Check if user has access to specific resources
		if len(teamUser.Permissions.Apps.Allowed) > 0 ||
			len(teamUser.Permissions.Channels.Allowed) > 0 ||
			len(teamUser.Permissions.Platforms.Allowed) > 0 ||
			len(teamUser.Permissions.Archs.Allowed) > 0 {
			// Store the allowed resources in context for later use
			c.Set("allowed_apps", teamUser.Permissions.Apps.Allowed)
			c.Set("allowed_channels", teamUser.Permissions.Channels.Allowed)
			c.Set("allowed_platforms", teamUser.Permissions.Platforms.Allowed)
			c.Set("allowed_archs", teamUser.Permissions.Archs.Allowed)
		}

		c.Next()
	}
}

// AdminOnlyMiddleware checks if the user is an admin
// This function should be called with the database connection
func AdminOnlyMiddleware(database *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isAPIToken, exists := c.Get("is_api_token"); exists {
			if apiTokenValue, ok := isAPIToken.(bool); ok && apiTokenValue {
				c.JSON(http.StatusForbidden, gin.H{"error": "Admin JWT is required"})
				c.Abort()
				return
			}
		}

		username, err := GetUsernameFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Check if user is an admin
		adminsCollection := database.Collection("admins")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()

		var adminUser bson.M
		err = adminsCollection.FindOne(ctx, bson.M{"username": username}).Decode(&adminUser)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		// User is an admin, allow access
		c.Next()
	}
}
