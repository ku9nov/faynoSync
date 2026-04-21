package utils

import (
	"context"
	"errors"
	"net/http"

	"faynoSync/server/model"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Maybe use the same flow for main API?

const ownerContextKey = "owner"

func ResolveRequestOwner(ctx context.Context, username string, database *mongo.Database) (string, error) {
	teamUsersCollection := database.Collection("team_users")
	var teamUser model.TeamUser
	err := teamUsersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&teamUser)
	if err == nil {
		return teamUser.Owner, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return username, nil
	}
	return "", err
}

func ResolveOwnerMiddleware(database *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, err := GetUsernameFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		owner, err := ResolveRequestOwner(c.Request.Context(), username, database)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve owner"})
			c.Abort()
			return
		}

		c.Set(ownerContextKey, owner)
		c.Next()
	}
}

func GetOwnerFromContext(c *gin.Context) (string, error) {
	if owner, exists := c.Get(ownerContextKey); exists {
		ownerString, ok := owner.(string)
		if ok && ownerString != "" {
			return ownerString, nil
		}
	}

	return GetUsernameFromContext(c)
}
