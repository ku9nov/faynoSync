package sign

import (
	"context"
	"faynoSync/server/utils"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Compared against when the user does not exist, so response time does not reveal which usernames exist.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		logrus.Errorf("Failed to generate dummy password hash: %v", err)
	}
	return hash
})

func Login(c *gin.Context, database *mongo.Database, rdb *redis.Client) {
	now := timeNow()
	if !enforceRateLimits(c, rdb, []rateLimit{loginIPLimit(c)}, now) {
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&credentials); err != nil {
		logrus.Errorf("Failed to bind JSON: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	usernameLimit := loginUsernameLimit(credentials.Username)
	if !enforceRateLimits(c, rdb, []rateLimit{usernameLimit}, now) {
		return
	}

	logrus.Infof("Login attempt for user: %s", credentials.Username)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// First check if user is an admin
	admins := database.Collection("admins")
	var adminResult bson.M
	err := admins.FindOne(ctx, bson.M{"username": credentials.Username}).Decode(&adminResult)

	if err == nil {
		logrus.Debugf("User %s found in admins collection", credentials.Username)
		// User is an admin, verify password
		hashedPassword := adminResult["password"].(string)
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
			logrus.Errorf("Invalid password for admin user %s: %v", credentials.Username, err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		logrus.Infof("Admin user %s successfully authenticated", credentials.Username)
		resetRateLimit(ctx, rdb, usernameLimit, now)
		// Create JWT token
		token, err := utils.GenerateJWT(credentials.Username)
		if err != nil {
			logrus.Errorf("Failed to generate JWT token for admin user %s: %v", credentials.Username, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token})
		return
	}

	logrus.Debugf("User %s not found in admins collection, checking team users", credentials.Username)

	// If not an admin, check if user is a team user
	teamUsers := database.Collection("team_users")
	var teamUserResult bson.M
	err = teamUsers.FindOne(ctx, bson.M{"username": credentials.Username}).Decode(&teamUserResult)

	if err != nil {
		logrus.Errorf("User %s not found in team_users collection: %v", credentials.Username, err)
		bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(credentials.Password))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	logrus.Debugf("User %s found in team_users collection", credentials.Username)

	// User is a team user, verify password
	hashedPassword := teamUserResult["password"].(string)
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		logrus.Errorf("Invalid password for team user %s: %v", credentials.Username, err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	logrus.Infof("Team user %s successfully authenticated", credentials.Username)
	resetRateLimit(ctx, rdb, usernameLimit, now)

	// Create JWT token
	token, err := utils.GenerateJWT(credentials.Username)
	if err != nil {
		logrus.Errorf("Failed to generate JWT token for team user %s: %v", credentials.Username, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
