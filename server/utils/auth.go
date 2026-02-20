package utils

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func AuthMiddleware(databases ...*mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var database *mongo.Database
		if len(databases) > 0 {
			database = databases[0]
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		// Extract the token from the "Bearer" scheme
		tokenParts := strings.Fields(authHeader)
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
			return
		}

		tokenString := tokenParts[1]

		// Validate the JWT token
		token, err := ValidateJWT(tokenString)
		if err == nil {
			// Extract claims and set the username in the context
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
				return
			}

			username, ok := claims["username"].(string)
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "username not found in claims"})
				return
			}

			c.Set("username", username)
			c.Next()
			return
		}

		// API tokens are only accepted in fns_ format.
		if !IsAPIToken(tokenString) {
			var errMsg string
			switch {
			case errors.Is(err, jwt.ErrTokenSignatureInvalid):
				errMsg = "invalid token signature"
			case errors.Is(err, jwt.ErrTokenMalformed):
				errMsg = "malformed token"
			case errors.Is(err, jwt.ErrTokenUnverifiable):
				errMsg = "unverifiable token"
			case errors.Is(err, jwt.ErrTokenExpired):
				errMsg = "token expired"
			case errors.Is(err, jwt.ErrTokenNotValidYet):
				errMsg = "token not active yet"
			default:
				errMsg = "invalid or expired token"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errMsg})
			return
		}

		if database == nil {
			logrus.Warn("API token received but AuthMiddleware initialized without database")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		tokenCollection := database.Collection("api_tokens")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		var apiToken model.APIToken
		if lookupErr := tokenCollection.FindOne(ctx, bson.M{"token_hash": HashAPIToken(tokenString)}).Decode(&apiToken); lookupErr != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		if apiToken.ExpiresAt != nil && apiToken.ExpiresAt.Before(time.Now()) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			return
		}

		now := time.Now()
		if _, updateErr := tokenCollection.UpdateOne(
			ctx,
			bson.M{"_id": apiToken.ID},
			bson.M{"$set": bson.M{"last_used_at": now}},
		); updateErr != nil {
			logrus.Warnf("Failed to update api token last_used_at for %s: %v", apiToken.ID.Hex(), updateErr)
		}

		c.Set("username", apiToken.Owner)
		c.Set("is_api_token", true)
		c.Set("api_token_id", apiToken.ID.Hex())
		c.Set("allowed_apps", apiToken.AllowedApps)
		c.Next()
	}
}
