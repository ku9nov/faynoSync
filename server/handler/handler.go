package handler

import (
	db "SAU/mongod"
	"SAU/server/handler/catalog"
	"SAU/server/handler/create"
	"SAU/server/handler/delete"
	"SAU/server/handler/info"
	"SAU/server/handler/sign"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

type AppHandler interface {
	GetAllApps(*gin.Context)
	GetAppByName(*gin.Context)
	DeleteApp(*gin.Context)
	DeleteChannel(*gin.Context)
	DeletePlatform(*gin.Context)
	DeleteArch(*gin.Context)
	DeletePackage(*gin.Context)
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
	CreatePackage(*gin.Context)
	ListPackages(*gin.Context)
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
	// Call the HealthCheck function from the info package
	info.HealthCheck(c, ch.client)
}

func (ch *appHandler) FindLatestVersion(c *gin.Context) {
	// Call the FindLatestVersion function from the info package
	info.FindLatestVersion(c, ch.repository, ch.database)
}

func (ch *appHandler) GetAppByName(c *gin.Context) {
	// Call the GetAppByName function from the catalog package
	catalog.GetAppByName(c, ch.repository)
}

func (ch *appHandler) GetAllApps(c *gin.Context) {
	// Call the GetAllApps function from the catalog package
	catalog.GetAllApps(c, ch.repository)
}

func (ch *appHandler) ListChannels(c *gin.Context) {
	// Call the ListChannels function from the catalog package
	catalog.ListChannels(c, ch.repository)
}

func (ch *appHandler) ListPlatforms(c *gin.Context) {
	// Call the ListPlatforms function from the catalog package
	catalog.ListPlatforms(c, ch.repository)
}

func (ch *appHandler) ListArchs(c *gin.Context) {
	// Call the ListArchs function from the catalog package
	catalog.ListArchs(c, ch.repository)
}

func (ch *appHandler) ListPackages(c *gin.Context) {
	// Call the ListPackages function from the catalog package
	catalog.ListPackages(c, ch.repository)
}

func (ch *appHandler) CreateChannel(c *gin.Context) {
	// Call the CreateChannel function from the create package
	create.CreateChannel(c, ch.repository)
}

func (ch *appHandler) CreatePlatform(c *gin.Context) {
	// Call the CreatePlatform function from the create package
	create.CreatePlatform(c, ch.repository)
}
func (ch *appHandler) CreateArch(c *gin.Context) {
	// Call the CreateArch function from the create package
	create.CreateArch(c, ch.repository)
}

func (ch *appHandler) CreatePackage(c *gin.Context) {
	// Call the CreatePackage function from the create package
	create.CreatePackage(c, ch.repository)
}

func (ch *appHandler) UploadApp(c *gin.Context) {
	// Call the UploadApp function from the create package
	create.UploadApp(c, ch.repository, ch.database)
}

func (ch *appHandler) Login(c *gin.Context) {
	// Call the Login function from the sign package
	sign.Login(c, ch.database)
}

func (ch *appHandler) DeleteApp(c *gin.Context) {
	// Call the DeleteApp function from the delete package
	delete.DeleteApp(c, ch.repository)
}

func (ch *appHandler) DeleteChannel(c *gin.Context) {
	// Call the DeleteChannel function from the delete package
	delete.DeleteChannel(c, ch.repository)
}

func (ch *appHandler) DeletePlatform(c *gin.Context) {
	// Call the DeletePlatform function from the delete package
	delete.DeletePlatform(c, ch.repository)
}

func (ch *appHandler) DeleteArch(c *gin.Context) {
	// Call the DeleteArch function from the delete package
	delete.DeleteArch(c, ch.repository)
}

func (ch *appHandler) DeletePackage(c *gin.Context) {
	// Call the DeletePackage function from the delete package
	delete.DeletePackage(c, ch.repository)
}
