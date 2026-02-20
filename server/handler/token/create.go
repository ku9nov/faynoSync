package token

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

func CreateToken(c *gin.Context, database *mongo.Database) {
	var req model.CreateAPITokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be in the future"})
		return
	}

	allowedApps, err := validateAllowedApps(c.Request.Context(), database, owner, req.AllowedApps)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rawToken, tokenPrefix, tokenHash, err := utils.GenerateAPIToken()
	if err != nil {
		logrus.Errorf("Failed to generate API token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	now := time.Now()
	tokenDoc := model.APIToken{
		ID:          primitive.NewObjectID(),
		Name:        req.Name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		Owner:       owner,
		AllowedApps: allowedApps,
		ExpiresAt:   req.ExpiresAt,
		CreatedAt:   now,
	}

	collection := database.Collection("api_tokens")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	if _, err := collection.InsertOne(ctx, tokenDoc); err != nil {
		logrus.Errorf("Failed to insert API token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           tokenDoc.ID,
		"name":         tokenDoc.Name,
		"token":        rawToken,
		"token_prefix": tokenDoc.TokenPrefix,
		"allowed_apps": tokenDoc.AllowedApps,
		"expires_at":   tokenDoc.ExpiresAt,
		"created_at":   tokenDoc.CreatedAt,
	})
}

func validateAllowedApps(ctx context.Context, database *mongo.Database, owner string, appIDs []string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	uniqueAppIDs := make([]string, 0, len(appIDs))
	seenAppIDs := make(map[string]struct{}, len(appIDs))
	for _, appID := range appIDs {
		if _, exists := seenAppIDs[appID]; exists {
			continue
		}
		seenAppIDs[appID] = struct{}{}
		uniqueAppIDs = append(uniqueAppIDs, appID)
	}

	uniqueObjectIDs := make([]primitive.ObjectID, 0, len(uniqueAppIDs))
	for _, appID := range uniqueAppIDs {
		objID, err := primitive.ObjectIDFromHex(appID)
		if err != nil {
			return nil, err
		}
		uniqueObjectIDs = append(uniqueObjectIDs, objID)
	}

	metaCollection := database.Collection("apps_meta")
	count, err := metaCollection.CountDocuments(ctx, bson.M{
		"_id":   bson.M{"$in": uniqueObjectIDs},
		"owner": owner,
		"app_name": bson.M{
			"$exists": true,
			"$ne":     nil,
		},
	})
	if err != nil {
		return nil, err
	}

	if count != int64(len(uniqueObjectIDs)) {
		return nil, errors.New("one or more allowed_apps are invalid or not owned by the admin")
	}

	return uniqueAppIDs, nil
}
