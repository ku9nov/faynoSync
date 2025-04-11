package team

import (
	"context"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type DeleteTeamUserRequest struct {
	UserID string `json:"id" binding:"required"`
}

// DeleteTeamUser deletes a team user by ObjectID
// This function should be called from the handler with the database connection
func DeleteTeamUser(c *gin.Context, database *mongo.Database) {
	var req DeleteTeamUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	logrus.Debugf("Deleting team user with ID: %s", req.UserID)

	// Get owner (admin) username from context
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get username from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("Admin attempting to delete team user: %s", owner)

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(req.UserID)
	if err != nil {
		logrus.Errorf("Invalid ObjectID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Find the team user to verify ownership
	collection := database.Collection("team_users")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// First check if the user exists and belongs to the admin
	var teamUser bson.M
	err = collection.FindOne(ctx, bson.M{
		"_id":   objectID,
		"owner": owner,
	}).Decode(&teamUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			logrus.Errorf("Team user not found or not owned by admin: %s", req.UserID)
			c.JSON(http.StatusNotFound, gin.H{"error": "Team user not found or you don't have permission to delete it"})
			return
		}
		logrus.Errorf("Error finding team user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find team user"})
		return
	}

	// Delete the team user
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objectID})
	if err != nil {
		logrus.Errorf("Failed to delete team user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete team user"})
		return
	}

	logrus.Debugf("Team user deleted successfully with ID: %s", req.UserID)
	c.JSON(http.StatusOK, gin.H{"message": "Team user deleted successfully"})
}
