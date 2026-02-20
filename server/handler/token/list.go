package token

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
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ListTokens(c *gin.Context, database *mongo.Database) {
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	collection := database.Collection("api_tokens")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	findOptions := options.Find()
	findOptions.SetSort(bson.D{{Key: "created_at", Value: -1}})
	findOptions.SetProjection(bson.M{"token_hash": 0})

	cursor, err := collection.Find(ctx, bson.M{"owner": owner}, findOptions)
	if err != nil {
		logrus.Errorf("Failed to list API tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tokens"})
		return
	}
	defer cursor.Close(ctx)

	response := make([]model.APITokenResponse, 0)
	for cursor.Next(ctx) {
		var token model.APIToken
		if err := cursor.Decode(&token); err != nil {
			logrus.Errorf("Failed to decode API token: %v", err)
			continue
		}

		response = append(response, model.APITokenResponse{
			ID:          token.ID,
			Name:        token.Name,
			TokenPrefix: token.TokenPrefix,
			AllowedApps: token.AllowedApps,
			ExpiresAt:   token.ExpiresAt,
			CreatedAt:   token.CreatedAt,
			LastUsedAt:  token.LastUsedAt,
		})
	}

	if err := cursor.Err(); err != nil {
		logrus.Errorf("Cursor error while listing API tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": response})
}
