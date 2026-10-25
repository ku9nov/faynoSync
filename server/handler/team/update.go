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
	"golang.org/x/crypto/bcrypt"
)

type UpdateTeamUserRequest struct {
	ID          string             `json:"id" binding:"required"`
	Username    string             `json:"username" binding:"required"`
	Password    string             `json:"password,omitempty"`
	Permissions *model.Permissions `json:"permissions,omitempty"`
}

// UpdateTeamUser updates a team user's information
// This function should be called from the handler with the database connection
func UpdateTeamUser(c *gin.Context, database *mongo.Database) {
	var req UpdateTeamUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	logrus.Debugf("Updating team user: %s", req.Username)

	// Get owner (admin) username from context
	adminUsername, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get username from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("Admin updating team user: %s", adminUsername)

	// Find the team user to update
	collection := database.Collection("team_users")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(req.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var teamUser model.TeamUser
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&teamUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			logrus.Errorf("Team user with id %s not found", req.ID)
			c.JSON(http.StatusNotFound, gin.H{"error": "Team user not found"})
			return
		}
		logrus.Errorf("Error finding team user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find team user"})
		return
	}

	// Check if the admin is the owner of this team user
	if teamUser.Owner != adminUsername {
		logrus.Errorf("Admin %s is not the owner of team user %s", adminUsername, req.Username)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not the owner of this team user"})
		return
	}

	taken, err := utils.UsernameTaken(ctx, req.Username, &objID, database)
	if err != nil {
		logrus.Errorf("Failed to check username uniqueness: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update team user"})
		return
	}
	if taken {
		logrus.Errorf("Username already exists: %s", req.Username)
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Prepare update document
	update := bson.M{"username": req.Username}

	// Update password if provided
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			logrus.Errorf("Failed to hash password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
			return
		}
		update["password"] = string(hashedPassword)
	}

	// A nil pointer means permissions were omitted; an all-false object is an explicit revoke
	if req.Permissions != nil {
		update["permissions"] = *req.Permissions
	}

	// Update the updated_at timestamp
	update["updated_at"] = primitive.NewDateTimeFromTime(time.Now())

	// Outstanding sessions must not survive a rename (the old name becomes free) or a password change.
	changes := bson.M{"$set": update}
	if req.Username != teamUser.Username || req.Password != "" {
		changes["$inc"] = bson.M{"token_version": int64(1)}
	}

	// Apply the update
	_, err = collection.UpdateOne(
		ctx,
		bson.M{"_id": objID},
		changes,
	)
	if err != nil {
		logrus.Errorf("Failed to update team user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update team user"})
		return
	}

	logrus.Infof("Team user with id %s updated successfully: %s", req.ID, req.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Team user updated successfully"})
}
