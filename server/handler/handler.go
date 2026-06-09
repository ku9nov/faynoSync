package handler

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/handler/catalog"
	"faynoSync/server/handler/create"
	"faynoSync/server/handler/delete"
	"faynoSync/server/handler/download"
	"faynoSync/server/handler/info"
	"faynoSync/server/handler/report"
	"faynoSync/server/handler/sign"
	"faynoSync/server/handler/team"
	"faynoSync/server/handler/token"
	"faynoSync/server/handler/update"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

type AppHandler interface {
	// GetAllApps(*gin.Context)
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
	FetchLatestVersionOfApp(*gin.Context)
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
	DeleteSpecificArtifactOfApp(*gin.Context)
	DownloadArtifact(*gin.Context)
	CreateTeamUser(*gin.Context)
	UpdateTeamUser(*gin.Context)
	ListTeamUsers(*gin.Context)
	DeleteTeamUser(*gin.Context)
	Whoami(*gin.Context)
	UpdateAdmin(*gin.Context)
	GetTelemetry(*gin.Context)
	TelemetryBeacon(*gin.Context)
	SquirrelReleases(*gin.Context)
	CreateToken(*gin.Context)
	ListTokens(*gin.Context)
	DeleteToken(*gin.Context)
	ListReportKeys(*gin.Context)
	RegenerateReportKey(*gin.Context)
	IngestReport(*gin.Context)
	ListReportGroups(*gin.Context)
	ListReportGroupBlobs(*gin.Context)
}

type appHandler struct {
	client          *mongo.Client
	repository      db.AppRepository
	database        *mongo.Database
	redisClient     *redis.Client
	performanceMode bool
}

func NewAppHandler(client *mongo.Client, repo db.AppRepository, db *mongo.Database, redisClient *redis.Client, performanceMode bool) AppHandler {
	h := &appHandler{client: client, repository: repo, database: db, redisClient: redisClient, performanceMode: performanceMode}
	h.reloadTelemetryAllowList(context.Background(), "initializing app handler")
	return h
}

func (ch *appHandler) HealthCheck(c *gin.Context) {
	// Call the HealthCheck function from the info package
	info.HealthCheck(c, ch.client, ch.redisClient, ch.performanceMode)
}

func (ch *appHandler) FindLatestVersion(c *gin.Context) {
	// Call the FindLatestVersion function from the info package
	info.FindLatestVersion(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
}

func (ch *appHandler) FetchLatestVersionOfApp(c *gin.Context) {
	// Call the FetchLatestVersionOfApp function from the info package
	info.FetchLatestVersionOfApp(c, ch.repository, ch.redisClient, ch.performanceMode)
}

func (ch *appHandler) GetAppByName(c *gin.Context) {
	// Call the GetAppByName function from the catalog package
	catalog.GetAppByName(c, ch.repository)
}

// func (ch *appHandler) GetAllApps(c *gin.Context) {
// 	// Call the GetAllApps function from the catalog package
// 	catalog.GetAllApps(c, ch.repository)
// }

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
	ch.reloadTelemetryAllowListAfterSuccess(c, "creating channel")
}

func (ch *appHandler) CreatePlatform(c *gin.Context) {
	// Call the CreatePlatform function from the create package
	create.CreatePlatform(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "creating platform")
}
func (ch *appHandler) CreateArch(c *gin.Context) {
	// Call the CreateArch function from the create package
	create.CreateArch(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "creating architecture")
}

func (ch *appHandler) CreateApp(c *gin.Context) {
	// Call the CreateApp function from the create package
	create.CreateApp(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "creating app")
}

func (ch *appHandler) UploadApp(c *gin.Context) {
	// Call the UploadApp function from the create package
	create.UploadApp(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
	ch.reloadTelemetryAllowListAfterSuccess(c, "uploading app version")
}

func (ch *appHandler) UpdateSpecificApp(c *gin.Context) {
	// Call the UpdateSpecificApp function from the create package
	update.UpdateSpecificApp(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
	ch.reloadTelemetryAllowListAfterSuccess(c, "updating app version")
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
	ch.reloadTelemetryAllowListAfterSuccess(c, "deleting app")
}

func (ch *appHandler) DeleteSpecificVersionOfApp(c *gin.Context) {
	// Call the DeleteSpecificVersionOfApp function from the delete package
	delete.DeleteSpecificVersionOfApp(c, ch.repository, ch.database, ch.redisClient)
	ch.reloadTelemetryAllowListAfterSuccess(c, "deleting app version")
}

func (ch *appHandler) DeleteChannel(c *gin.Context) {
	// Call the DeleteChannel function from the delete package
	delete.DeleteChannel(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "deleting channel")
}

func (ch *appHandler) DeletePlatform(c *gin.Context) {
	// Call the DeletePlatform function from the delete package
	delete.DeletePlatform(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "deleting platform")
}

func (ch *appHandler) DeleteArch(c *gin.Context) {
	// Call the DeleteArch function from the delete package
	delete.DeleteArch(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "deleting architecture")
}

func (ch *appHandler) UpdateApp(c *gin.Context) {
	// Call the UpdateApp function from the create package
	update.UpdateApp(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "updating app")
}

func (ch *appHandler) UpdateChannel(c *gin.Context) {
	// Call the UpdateChannel function from the create package
	update.UpdateChannel(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "updating channel")
}

func (ch *appHandler) UpdatePlatform(c *gin.Context) {
	// Call the UpdatePlatform function from the create package
	update.UpdatePlatform(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "updating platform")
}

func (ch *appHandler) UpdateArch(c *gin.Context) {
	// Call the UpdateArch function from the create package
	update.UpdateArch(c, ch.repository)
	ch.reloadTelemetryAllowListAfterSuccess(c, "updating architecture")
}
func (ch *appHandler) DeleteSpecificArtifactOfApp(c *gin.Context) {
	// Call the DeleteSpecificArtifactOfApp function from the delete package
	delete.DeleteSpecificArtifactOfApp(c, ch.repository, ch.database, ch.redisClient)
	ch.reloadTelemetryAllowListAfterSuccess(c, "deleting app artifact")
}

func (ch *appHandler) DownloadArtifact(c *gin.Context) {
	// Call the DownloadArtifact function from the download package
	download.DownloadArtifact(c)
}

func (ch *appHandler) CreateTeamUser(c *gin.Context) {
	team.CreateTeamUser(c, ch.database)
}

func (ch *appHandler) UpdateTeamUser(c *gin.Context) {
	team.UpdateTeamUser(c, ch.database)
}

func (ch *appHandler) ListTeamUsers(c *gin.Context) {
	team.ListTeamUsers(c, ch.database)
}

func (ch *appHandler) DeleteTeamUser(c *gin.Context) {
	team.DeleteTeamUser(c, ch.database)
}

func (ch *appHandler) Whoami(c *gin.Context) {
	team.Whoami(c, ch.database)
}

func (ch *appHandler) UpdateAdmin(c *gin.Context) {
	update.UpdateAdmin(c, ch.database)
}

func (ch *appHandler) GetTelemetry(c *gin.Context) {
	info.GetTelemetry(c, ch.redisClient, ch.database)
}

func (ch *appHandler) TelemetryBeacon(c *gin.Context) {
	info.TelemetryBeacon(c, ch.redisClient)
}

func (ch *appHandler) SquirrelReleases(c *gin.Context) {
	owner := c.Param("owner")
	app := c.Param("app")
	channel := c.Param("channel")
	platform := c.Param("platform")
	arch := c.Param("arch")
	version := c.Param("version")

	q := c.Request.URL.Query()
	q.Set("owner", owner)
	q.Set("app_name", app)
	q.Set("channel", channel)
	q.Set("platform", platform)
	q.Set("arch", arch)
	q.Set("version", version)
	q.Set("updater", "squirrel_windows")

	c.Request.URL.RawQuery = q.Encode()

	info.FindLatestVersion(c, ch.repository, ch.database, ch.redisClient, ch.performanceMode)
}

func (ch *appHandler) CreateToken(c *gin.Context) {
	token.CreateToken(c, ch.database)
}

func (ch *appHandler) ListTokens(c *gin.Context) {
	token.ListTokens(c, ch.database)
}

func (ch *appHandler) DeleteToken(c *gin.Context) {
	token.DeleteToken(c, ch.database)
}

func (ch *appHandler) ListReportKeys(c *gin.Context) {
	report.ListReportKeys(c, ch.repository)
}

func (ch *appHandler) RegenerateReportKey(c *gin.Context) {
	report.RegenerateReportKey(c, ch.repository)
}

func (ch *appHandler) IngestReport(c *gin.Context) {
	report.IngestReport(c, ch.repository, ch.redisClient)
}

func (ch *appHandler) ListReportGroups(c *gin.Context) {
	report.ListReportGroups(c, ch.repository)
}

func (ch *appHandler) ListReportGroupBlobs(c *gin.Context) {
	report.ListReportGroupBlobs(c, ch.repository)
}

func (ch *appHandler) reloadTelemetryAllowListAfterSuccess(c *gin.Context, reason string) {
	status := c.Writer.Status()
	if status < 200 || status >= 400 {
		logrus.Debugf("Telemetry allow-list reload skipped after %s because response status is %d", reason, status)
		return
	}
	ch.reloadTelemetryAllowList(context.Background(), reason)
}

func (ch *appHandler) reloadTelemetryAllowList(parent context.Context, reason string) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	if err := info.ReloadTelemetryAllowList(ctx, ch.database); err != nil {
		logrus.WithError(err).Errorf("Failed to reload telemetry allow-list after %s", reason)
		return
	}
	logrus.Debugf("Telemetry allow-list reloaded after %s", reason)
}
