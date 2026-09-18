package info

import (
	"context"
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// errAppNotFound is aliased because FindLatestVersion shadows the mongod package alias with its own db parameter.
var errAppNotFound = db.ErrAppNotFound

// authorizeReadRequest is the gate shared by /checkVersion and /apps/latest. It runs before the response cache,
// so a private app never reaches the cache at all: one indexed lookup per request is cheaper than any scheme that
// would let a private app share a cache with anonymous callers.
//
// It answers the request itself when the app is unknown or the caller is denied, and reports whether the handler
// may go on to build a response.
func authorizeReadRequest(ctx context.Context, c *gin.Context, repository db.AppRepository, params map[string]interface{}, notFoundStatus int) (*model.AppAccess, bool) {
	owner, _ := params["owner"].(string)
	appName, _ := params["app_name"].(string)
	channel, _ := params["channel"].(string)

	access, err := repository.ResolveAppAccess(ctx, owner, appName, channel)
	if err != nil {
		if errors.Is(err, errAppNotFound) {
			respondAppNotFound(c, notFoundStatus)
			return nil, false
		}
		logrus.Error("Error in ResolveAppAccess: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve app"})
		return nil, false
	}

	allowed, err := authorizeRead(ctx, c, repository, access)
	if err != nil {
		logrus.Error("Error in authorizeRead: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authorize request"})
		return nil, false
	}
	if !allowed {
		respondAppNotFound(c, notFoundStatus)
		return nil, false
	}

	return access, true
}

// authorizeRead decides whether a read path may say anything about the app.
func authorizeRead(ctx context.Context, c *gin.Context, repository db.AppRepository, access *model.AppAccess) (bool, error) {
	if !access.Private {
		return true, nil
	}

	artifact := &model.PrivateArtifact{
		AppID:        access.AppID,
		ChannelID:    access.ChannelID,
		Owner:        access.Owner,
		DownloadMode: access.DownloadMode,
	}

	if tokenString, ok := utils.BearerToken(c.GetHeader("Authorization")); ok {
		if username, err := utils.UsernameFromJWT(tokenString); err == nil {
			allowed, err := repository.CanDownloadPrivateArtifact(ctx, username, artifact)
			if err != nil {
				return false, err
			}
			if allowed {
				return true, nil
			}
		}
	}

	if access.DownloadMode == utils.DownloadModeUnlisted {
		return true, nil
	}

	if downloadToken := c.GetHeader(utils.DownloadTokenHeader); downloadToken != "" {
		return repository.HasDownloadToken(ctx, downloadToken, artifact)
	}

	return false, nil
}

// respondAppNotFound is the only answer a denied request gets: it must stay identical to the answer for an app
// that does not exist, otherwise an anonymous caller can probe which private apps and channels are there.
func respondAppNotFound(c *gin.Context, httpStatus int) {
	c.JSON(httpStatus, gin.H{"error": utils.ErrAppNotFound.Error()})
}
