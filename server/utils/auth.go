package utils

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
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
		if err != nil {
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

		// Set the username in the context for later use
		c.Set("username", username)
		c.Next()
	}
}
