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

type CreateTeamUserRequest struct {
	Username    string            `json:"username" binding:"required"`
	Password    string            `json:"password" binding:"required"`
	Permissions model.Permissions `json:"permissions" binding:"required"`
}

// CreateTeamUser creates a new team user
// This function should be called from the handler with the database connection
func CreateTeamUser(c *gin.Context, database *mongo.Database) {
	var req CreateTeamUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	logrus.Debugf("Creating team user: %s", req.Username)

	// Get owner (admin) username from context
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get username from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("Team user will be owned by admin: %s", owner)

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logrus.Errorf("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Create team user document
	teamUser := model.TeamUser{
		ID:          primitive.NewObjectID(),
		Username:    req.Username,
		Password:    string(hashedPassword),
		Owner:       owner,
		Updated_at:  primitive.NewDateTimeFromTime(time.Now()),
		Permissions: req.Permissions,
	}

	logrus.Debugf("Team user document created: %+v", teamUser)

	// Insert into database
	collection := database.Collection("team_users")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Check if username already exists
	var existingUser bson.M
	err = collection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&existingUser)
	if err == nil {
		logrus.Errorf("Username already exists: %s", req.Username)
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	_, err = collection.InsertOne(ctx, teamUser)
	if err != nil {
		logrus.Errorf("Failed to insert team user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create team user"})
		return
	}

	logrus.Debugf("Team user created successfully with ID: %s", teamUser.ID.Hex())
	c.JSON(http.StatusOK, gin.H{"message": "Team user created successfully"})
}
