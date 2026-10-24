package sign

import (
	"context"
	"crypto/subtle"
	"faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

func SignUp(c *gin.Context, database *mongo.Database, client *mongo.Client, rdb *redis.Client) {
	if !enforceRateLimits(c, rdb, []rateLimit{signupIPLimit(c), signupGlobalLimit}, timeNow()) {
		return
	}

	var creds model.Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" || subtle.ConstantTimeCompare([]byte(creds.SecretKey), []byte(apiKey)) != 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "wrong api key"})
		return
	}
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	taken, err := utils.UsernameTaken(ctx, creds.Username, nil, database)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to check username"})
		return
	}
	if taken {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user already exists"})
		return
	}
	err = mongod.CreateUser(client, database, &creds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
	} else {
		c.JSON(http.StatusOK, gin.H{"result": "Successfully created admin user."})
	}
}
