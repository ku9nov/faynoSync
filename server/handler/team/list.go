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
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TeamUserResponse represents the response for a team user
type TeamUserResponse struct {
	ID          primitive.ObjectID `json:"id"`
	Username    string             `json:"username"`
	Permissions model.Permissions  `json:"permissions"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// ListTeamUsers returns a list of team users owned by the admin
func ListTeamUsers(c *gin.Context, database *mongo.Database) {
	// Get owner (admin) username from context
	adminUsername, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get username from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("Admin listing team users: %s", adminUsername)

	// Find all team users owned by this admin
	collection := database.Collection("team_users")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Set up find options
	findOptions := options.Find()
	findOptions.SetProjection(bson.M{"password": 0}) // Exclude password from results

	// Find all team users owned by this admin
	cursor, err := collection.Find(ctx, bson.M{"owner": adminUsername}, findOptions)
	if err != nil {
		logrus.Errorf("Failed to find team users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve team users"})
		return
	}
	defer cursor.Close(ctx)

	// Process results
	var teamUsers []TeamUserResponse
	for cursor.Next(ctx) {
		var teamUser model.TeamUser
		if err := cursor.Decode(&teamUser); err != nil {
			logrus.Errorf("Failed to decode team user: %v", err)
			continue
		}

		// Convert to response format
		response := TeamUserResponse{
			ID:          teamUser.ID,
			Username:    teamUser.Username,
			Permissions: teamUser.Permissions,
			UpdatedAt:   teamUser.Updated_at.Time(),
		}

		teamUsers = append(teamUsers, response)
	}

	if err := cursor.Err(); err != nil {
		logrus.Errorf("Cursor error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process team users"})
		return
	}

	logrus.Debugf("Found %d team users for admin %s", len(teamUsers), adminUsername)
	c.JSON(http.StatusOK, gin.H{"users": teamUsers})
}
