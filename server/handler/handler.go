package handler

import (
	db "faynoSync/mongod"
	"faynoSync/server/handler/catalog"
	"faynoSync/server/handler/create"
	"faynoSync/server/handler/delete"
	"faynoSync/server/handler/info"
	"faynoSync/server/handler/sign"
	"faynoSync/server/handler/update"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

type AppHandler interface {
	GetAllApps(*gin.Context)
	GetAppByName(*gin.Context)
	DeleteSpecificVersionOfApp(*gin.Context)
	DeleteApp(*gin.Context)
	DeleteChannel(*gin.Context)
	DeletePlatform(*gin.Context)
	DeleteArch(*gin.Context)
	UploadApp(*gin.Context)
	UpdateSpecificApp(*gin.Context)
	HealthCheck(*gin.Context)
	FindLatestVersion(*gin.Context)
	Login(*gin.Context)
	CreateChannel(*gin.Context)
	ListChannels(*gin.Context)
	CreatePlatform(*gin.Context)
	ListPlatforms(*gin.Context)
	CreateArch(*gin.Context)
	ListArchs(*gin.Context)
	CreateApp(*gin.Context)
	ListApps(*gin.Context)
	SignUp(*gin.Context)
	UpdateApp(*gin.Context)
	UpdateChannel(*gin.Context)
	UpdatePlatform(*gin.Context)
	UpdateArch(*gin.Context)
}

type appHandler struct {
	client          *mongo.Client
	repository      db.AppRepository
	database        *mongo.Database
	redisClient     *redis.Client
	performanceMode bool
	slack           bool
}

func NewAppHandler(client *mongo.Client, repo db.AppRepository, db *mongo.Database, redisClient *redis.Client, performanceMode bool) AppHandler {
	return &appHandler{client: client, repository: repo, database: db, redisClient: redisClient, performanceMode: performanceMode}
}

func (ch *appHandler) HealthCheck(c *gin.Context) {
	// Call the HealthCheck function from the info package
	info.HealthCheck(c, ch.client)
}

func (ch *appHandler) FindLatestVersion(c *gin.Context) {
	// Call the FindLatestVersion function from the info package
	info.FindLatestVersion(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
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
func (ch *appHandler) ListApps(c *gin.Context) {
	// Call the ListApps function from the catalog package
	catalog.ListApps(c, ch.repository)
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

func (ch *appHandler) CreateApp(c *gin.Context) {
	// Call the CreateApp function from the create package
	create.CreateApp(c, ch.repository)
}

func (ch *appHandler) UploadApp(c *gin.Context) {
	// Call the UploadApp function from the create package
	create.UploadApp(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
}

func (ch *appHandler) UpdateSpecificApp(c *gin.Context) {
	// Call the UpdateSpecificApp function from the create package
	update.UpdateSpecificApp(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
}

func (ch *appHandler) Login(c *gin.Context) {
	// Call the Login function from the sign package
	sign.Login(c, ch.database)
}

func (ch *appHandler) SignUp(c *gin.Context) {
	// Call the SignUp function from the sign package
	sign.SignUp(c, ch.database, ch.client)
}

func (ch *appHandler) DeleteApp(c *gin.Context) {
	// Call the DeleteApp function from the delete package
	delete.DeleteApp(c, ch.repository)
}

func (ch *appHandler) DeleteSpecificVersionOfApp(c *gin.Context) {
	// Call the DeleteSpecificVersionOfApp function from the delete package
	delete.DeleteSpecificVersionOfApp(c, ch.repository)
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

func (ch *appHandler) UpdateApp(c *gin.Context) {
	// Call the UpdateApp function from the create package
	update.UpdateApp(c, ch.repository)
}

func (ch *appHandler) UpdateChannel(c *gin.Context) {
	// Call the UpdateChannel function from the create package
	update.UpdateChannel(c, ch.repository)
}

func (ch *appHandler) UpdatePlatform(c *gin.Context) {
	// Call the UpdatePlatform function from the create package
	update.UpdatePlatform(c, ch.repository)
}

func (ch *appHandler) UpdateArch(c *gin.Context) {
	// Call the UpdateArch function from the create package
	update.UpdateArch(c, ch.repository)
}
