package team

import (
	"context"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// WhoamiResponse represents the response for the whoami endpoint
type WhoamiResponse struct {
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

	// First check if user is an admin
	adminsCollection := database.Collection("admins")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var adminUser bson.M
	err = adminsCollection.FindOne(ctx, bson.M{"username": username}).Decode(&adminUser)
	if err == nil {
		// User is an admin - just set is_admin flag
		response.IsAdmin = true
		c.JSON(http.StatusOK, response)
		return
	}
	logrus.Debugf("User is not an admin: %s", username)
	// If not admin, check team user permissions
	teamUsersCollection := database.Collection("team_users")
	var teamUser model.TeamUser
	err = teamUsersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&teamUser)
	if err != nil {
		logrus.Errorf("Failed to find user: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// User is a team user
	response.IsAdmin = false
	response.Owner = teamUser.Owner
	response.Permissions = &teamUser.Permissions

	c.JSON(http.StatusOK, response)
}
