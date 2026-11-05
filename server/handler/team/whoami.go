package team

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// WhoamiResponse represents the response for the whoami endpoint
type WhoamiResponse struct {
	ID          primitive.ObjectID `json:"id"`
	Username    string             `json:"username"`
	IsAdmin     bool               `json:"is_admin"`
	Owner       string             `json:"owner,omitempty"`
	Permissions *model.Permissions `json:"permissions,omitempty"`
}

// Whoami returns information about the current user
func Whoami(c *gin.Context, database *mongo.Database) {
	// Get username from context
	username, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get username from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("User requesting whoami: %s", username)

	// Create response structure
	response := WhoamiResponse{
		Username: username,
	}

	principal, ok := utils.PrincipalFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	if principal.Type == utils.PrincipalAdmin {
		// User is an admin - just set is_admin flag
		response.IsAdmin = true
		response.ID = principal.ID
		if response.ID.IsZero() {
			// API tokens carry the admin by name only; admins are looked up in admins, never in team_users.
			var adminUser bson.M
			if err := database.Collection("admins").FindOne(ctx, bson.M{"username": username}).Decode(&adminUser); err == nil {
				response.ID = adminUser["_id"].(primitive.ObjectID)
			}
		}
		c.JSON(http.StatusOK, response)
		return
	}
	logrus.Debugf("User is not an admin: %s", username)
	// If not admin, check team user permissions
	teamUserDoc, err := utils.CallerTeamUser(ctx, database)
	if err == nil && teamUserDoc == nil {
		err = errors.New("team user not found")
	}
	if err != nil {
		logrus.Errorf("Failed to find user: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	teamUser := *teamUserDoc
	// User is a team user
	response.IsAdmin = false
	response.Owner = teamUser.Owner
	response.Permissions = &teamUser.Permissions

	c.JSON(http.StatusOK, response)
}
