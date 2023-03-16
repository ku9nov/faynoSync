package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	db "SAU/mongod"
	"SAU/server/model"
	"SAU/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AppHandler interface {
	GetAllApps(*gin.Context)
	GetAppByName(*gin.Context)
	DeleteApp(*gin.Context)
	UploadApp(*gin.Context)
	HealthCheck(*gin.Context)
	FindLatestVersion(*gin.Context)
	Login(*gin.Context)
}

type appHandler struct {
	client     *mongo.Client
	repository db.AppRepository
	database   *mongo.Database
}

func NewAppHandler(client *mongo.Client, repo db.AppRepository, db *mongo.Database) AppHandler {
	return &appHandler{client: client, repository: repo, database: db}
}

func (ch *appHandler) HealthCheck(c *gin.Context) {

	ctx, ctxCancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer ctxCancel()

	if ctx.Err() != nil {
		err := fmt.Errorf("failed to create context with error: %v", ctx.Err())
		logrus.Error(err)
	}

	if err := ch.client.Ping(ctx, nil); err != nil {
		c.JSON(http.StatusFailedDependency, gin.H{"status": "unhealty"})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	}

}

func (ch *appHandler) GetAppByName(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var appList []*model.App

	//get parameter
	appName := c.Query("app_name")

	//request on repository
	if result, err := ch.repository.GetAppByName(appName, ctx); err != nil {
		logrus.Error(err)
	} else {
		appList = result
	}

	c.JSON(http.StatusOK, gin.H{"apps": appList})
}

func (ch *appHandler) DeleteApp(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		log.Fatal(err)
	}

	//request on repository
	link, result, err := ch.repository.Delete(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}

	index := strings.Index(link, "amazonaws.com/") + len("amazonaws.com/")
	if index > len(link) {
		// The link doesn't contain "amazonaws.com/"
		fmt.Println("Invalid link")
		return
	}
	subLink := link[index:]

	utils.DeleteFromS3(subLink, c, viper.GetViper())
	c.JSON(http.StatusOK, gin.H{"deleteResult.DeletedCount": result})
}

func (ch *appHandler) GetAllApps(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var appList []*model.App

	//request on repository
	if result, err := ch.repository.Get(ctx); err != nil {
		logrus.Error(err)
	} else {
		appList = result
	}

	c.JSON(http.StatusOK, gin.H{"apps": &appList})
}

func (ch *appHandler) UploadApp(c *gin.Context) {
	if !utils.IsValidInputAppName(c.Query("app_name")) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app_name parameter"})
		return
	}
	if !utils.IsValidInputVersion(c.Query("version")) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid version parameter"})
		return
	}
	// Get file from form data
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "file is required",
		})
		return
	}

	link := utils.UploadToS3(c.Query("app_name"), c.Query("version"), file, c, viper.GetViper())

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := ch.repository.Upload(c.Query("app_name"), c.Query("version"), link, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload app data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": result})
}

func (ch *appHandler) FindLatestVersion(c *gin.Context) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	//request on repository
	updateAvailable, linkToLatest, err := ch.repository.CheckLatestVersion(c.Query("app_name"), c.Query("version"), ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"update_available": updateAvailable, "update_url": linkToLatest})
}

func (ch *appHandler) Login(c *gin.Context) {
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
	admins := ch.database.Collection("admins")
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
