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
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type AppHandler interface {
	GetAllApps(*gin.Context)
	GetAppByName(*gin.Context)
	DeleteApp(*gin.Context)
	UploadApp(*gin.Context)
	HealthCheck(*gin.Context)
}

type appHandler struct {
	client     *mongo.Client
	repository db.AppRepository
}

func NewAppHandler(client *mongo.Client, repo db.AppRepository) AppHandler {
	return &appHandler{client: client, repository: repo}
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
	// Get file from form data
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "file is required",
		})
		return
	}

	// Extract app name and version from query params
	appName := c.Query("app_name")
	version := c.Query("version")

	link := utils.UploadToS3(appName, version, file, c, viper.GetViper())

	// Upload app data to MongoDB
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	result, err := ch.repository.Upload(appName, version, link, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload app data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": result})
}
