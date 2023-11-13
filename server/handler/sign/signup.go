package sign

import (
	"context"
	"faynoSync/mongod"
	"faynoSync/server/model"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SignUp(c *gin.Context, database *mongo.Database, client *mongo.Client) {
	var creds model.Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if creds.SecretKey != os.Getenv("API_KEY") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "wrong api key"})
		return
	}
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	// check the user credentials against the admins collection in MongoDB
	admins := database.Collection("admins")
	var result bson.M
	err := admins.FindOne(ctx, bson.M{"username": creds.Username}).Decode(&result)
	if err == nil {
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
