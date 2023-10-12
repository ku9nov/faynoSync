package sign

import (
	"SAU/server/utils"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func Login(c *gin.Context, database *mongo.Database) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&credentials); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// check the user credentials against the admins collection in MongoDB
	admins := database.Collection("admins")
	var result bson.M
	err := admins.FindOne(ctx, bson.M{"username": credentials.Username}).Decode(&result)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// compare the hashed passwords
	hashedPassword := result["password"].(string)
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}
	tokenBytes, err := utils.EncryptUserCredentials([]byte(credentials.Username + ":" + credentials.Password))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}
	token := string(tokenBytes)

	c.JSON(http.StatusOK, gin.H{"token": token})
}
