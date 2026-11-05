package create

import (
	"errors"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

// UploadRequest is the part of an upload that does not depend on how the files reach
// storage: who uploads, for which app, and with which parameters.
type UploadRequest struct {
	Username string
	Owner    string
	AppName  string
	Params   map[string]interface{}
}

// ResolveUploadRequest authenticates the caller, resolves the owner the artifacts are
// stored under and validates the request parameters.
func ResolveUploadRequest(c *gin.Context, database *mongo.Database) (UploadRequest, bool) {
	// Get username from JWT token
	username, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return UploadRequest{}, false
	}

	// Resolve the actual owner (admin) for S3 paths; team users must store under their admin
	owner, err := utils.ResolveRequestOwner(c.Request.Context(), username, database)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve owner"})
		return UploadRequest{}, false
	}

	ctxQueryMap, err := utils.ValidateParams(c, database, owner)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return UploadRequest{}, false
	}

	// Add intermediate field to ctxQueryMap if it exists in the request
	if intermediate := c.PostForm("intermediate"); intermediate != "" {
		ctxQueryMap["intermediate"] = intermediate
	}

	appName, ok := ctxQueryMap["app_name"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_name is required"})
		return UploadRequest{}, false
	}
	if err := utils.ValidateAPITokenAppScope(c, database, owner, appName); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return UploadRequest{}, false
	}
	// Checked before any object is written, so a team user cannot store files outside their allowed apps, channels, platforms and archs.
	if err := utils.EnsureTeamUserUploadAccess(c.Request.Context(), ctxQueryMap, database); err != nil {
		logrus.Error(err)
		utils.RespondTeamAccessError(c, err)
		return UploadRequest{}, false
	}

	return UploadRequest{Username: username, Owner: owner, AppName: appName, Params: ctxQueryMap}, true
}

// ResolveAppVisibility reports whether the app is private and rejects the updaters that
// need a publicly served feed.
func ResolveAppVisibility(c *gin.Context, database *mongo.Database, appName, owner string, params map[string]interface{}) (bool, bool) {
	checkAppVisibility, err := utils.CheckPrivate(appName, owner, database, c)
	if err != nil {
		logrus.Error(err)
		if errors.Is(err, utils.ErrAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return false, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return false, false
	}
	if updater, _ := params["updater"].(string); updater != "" {
		if err := updaters.ValidatePrivate(updater, checkAppVisibility); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return false, false
		}
	}

	return checkAppVisibility, true
}
