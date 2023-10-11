package handler

import (
	"context"
	"errors"
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
	DeleteChannel(*gin.Context)
	DeletePlatform(*gin.Context)
	DeleteArch(*gin.Context)
	UploadApp(*gin.Context)
	HealthCheck(*gin.Context)
	FindLatestVersion(*gin.Context)
	Login(*gin.Context)
	CreateChannel(*gin.Context)
	ListChannels(*gin.Context)
	CreatePlatform(*gin.Context)
	ListPlatforms(*gin.Context)
	CreateArch(*gin.Context)
	ListArchs(*gin.Context)
}

type appHandler struct {
	client     *mongo.Client
	repository db.AppRepository
	database   *mongo.Database
}

func NewAppHandler(client *mongo.Client, repo db.AppRepository, db *mongo.Database) AppHandler {
	return &appHandler{client: client, repository: repo, database: db}
}

func (ch *appHandler) validateParams(c *gin.Context) (map[string]interface{}, error) {
	ctxQueryMap := map[string]interface{}{
		"app_name": c.Query("app_name"),
		"version":  c.Query("version"),
		"channel":  c.Query("channel"),
		"publish":  c.Query("publish"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
	}

	if !utils.IsValidAppName(ctxQueryMap["app_name"].(string)) {
		return nil, errors.New("Invalid app_name parameter")
	}
	if !utils.IsValidVersion(ctxQueryMap["version"].(string)) {
		return nil, errors.New("Invalid version parameter")
	}
	if !utils.IsValidChannelName(ctxQueryMap["channel"].(string)) {
		return nil, errors.New("Invalid channel parameter")
	}

	if !utils.IsValidPlatformName(ctxQueryMap["platform"].(string)) {
		return nil, errors.New("Invalid platform parameter")
	}

	if !utils.IsValidArchName(ctxQueryMap["arch"].(string)) {
		return nil, errors.New("Invalid platform parameter")
	}

	errChannels := utils.CheckChannels(ctxQueryMap["channel"].(string), ch.database, c)
	if errChannels != nil {
		return nil, errChannels
	}

	errPlatforms := utils.CheckPlatforms(ctxQueryMap["platform"].(string), ch.database, c)
	if errPlatforms != nil {
		return nil, errPlatforms
	}

	errArchs := utils.CheckArchs(ctxQueryMap["arch"].(string), ch.database, c)
	if errArchs != nil {
		return nil, errArchs
	}

	return ctxQueryMap, nil
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
	link, result, err := ch.repository.DeleteApp(objID, ctx)
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
	c.JSON(http.StatusOK, gin.H{"deleteAppResult.DeletedCount": result})
}

func (ch *appHandler) DeleteChannel(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		log.Fatal(err)
	}

	//request on repository
	result, err := ch.repository.DeleteChannel(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"deleteChannelResult.DeletedCount": result})
}

func (ch *appHandler) DeletePlatform(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		log.Fatal(err)
	}

	//request on repository
	result, err := ch.repository.DeletePlatform(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"deletePlatformResult.DeletedCount": result})
}

func (ch *appHandler) DeleteArch(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		log.Fatal(err)
	}

	//request on repository
	result, err := ch.repository.DeleteArch(objID, ctx)
	if err != nil {
		logrus.Error(err)
	}
	c.JSON(http.StatusOK, gin.H{"deleteArchResult.DeletedCount": result})
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

func (ch *appHandler) ListChannels(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var channelsList []*model.Channel

	//request on repository
	if result, err := ch.repository.ListChannels(ctx); err != nil {
		logrus.Error(err)
	} else {
		channelsList = result
	}

	c.JSON(http.StatusOK, gin.H{"channels": &channelsList})
}

func (ch *appHandler) ListPlatforms(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var platformsList []*model.Platform

	//request on repository
	if result, err := ch.repository.ListPlatforms(ctx); err != nil {
		logrus.Error(err)
	} else {
		platformsList = result
	}

	c.JSON(http.StatusOK, gin.H{"platforms": &platformsList})
}

func (ch *appHandler) ListArchs(c *gin.Context) {

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	var archsList []*model.Arch

	//request on repository
	if result, err := ch.repository.ListArchs(ctx); err != nil {
		logrus.Error(err)
	} else {
		archsList = result
	}

	c.JSON(http.StatusOK, gin.H{"archs": &archsList})
}

func (ch *appHandler) CreateChannel(c *gin.Context) {

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := ch.repository.CreateChannel(c.Query("channel"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload channel data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createChannelResult.Created": result})
}

func (ch *appHandler) CreatePlatform(c *gin.Context) {

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := ch.repository.CreatePlatform(c.Query("platform"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload platform data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createPlatformResult.Created": result})
}
func (ch *appHandler) CreateArch(c *gin.Context) {

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := ch.repository.CreateArch(c.Query("arch"), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload arch data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"createArchResult.Created": result})
}

func (ch *appHandler) UploadApp(c *gin.Context) {
	ctxQueryMap, err := ch.validateParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

	link := utils.UploadToS3(ctxQueryMap, file, c, viper.GetViper())

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := ch.repository.Upload(ctxQueryMap, link, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": result})
}

func (ch *appHandler) FindLatestVersion(c *gin.Context) {
	_, err := ch.validateParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	//request on repository
	updateAvailable, linkToLatest, err := ch.repository.CheckLatestVersion(c.Query("app_name"), c.Query("version"), c.Query("channel"), c.Query("platform"), c.Query("arch"), ctx)
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
