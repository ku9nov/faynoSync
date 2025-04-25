package update

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
	"golang.org/x/crypto/bcrypt"
)

type UpdateAdminRequest struct {
	ID       string `json:"id" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password,omitempty"`
}

func UpdateAdmin(c *gin.Context, database *mongo.Database) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Get username from JWT token
	adminUsername, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Parse request body
	var req UpdateAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Verify that the username from JWT matches the request username
	if adminUsername != req.Username {
		logrus.Errorf("Username mismatch: JWT=%s, Request=%s", adminUsername, req.Username)
		c.JSON(http.StatusForbidden, gin.H{"error": "Username mismatch"})
		return
	}

	// Convert string ID to ObjectID
	objID, err := primitive.ObjectIDFromHex(req.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	// Find the admin in the database
	collection := database.Collection("admins")
	var adminUser bson.M
	err = collection.FindOne(ctx, bson.M{
		"_id":      objID,
		"username": req.Username,
	}).Decode(&adminUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			logrus.Errorf("Admin not found with id %s and username %s", req.ID, req.Username)
			c.JSON(http.StatusNotFound, gin.H{"error": "Admin not found"})
			return
		}
		logrus.Errorf("Error finding admin: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find admin"})
		return
	}

	// Prepare update document
	update := bson.M{}

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

	// Update the updated_at timestamp
	update["updated_at"] = time.Now()

	// Apply the update if there are changes
	if len(update) > 0 {
		_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": update})
		if err != nil {
			logrus.Errorf("Failed to update admin: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update admin"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Admin updated successfully"})
}
