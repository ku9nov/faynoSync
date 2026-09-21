package apierr

import (
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Respond answers with the status a repository error maps to, so every handler reports the same
// failure the same way: a refusal by permissions is 403, a missing app or channel 404, a download
// token asked for a public app 400, anything unexpected 500.
func Respond(c *gin.Context, err error) {
	var accessErr *db.AccessDeniedError
	switch {
	case errors.As(err, &accessErr):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, utils.ErrAppNotFound), errors.Is(err, db.ErrChannelNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, db.ErrDownloadTokenPublicApp), errors.Is(err, db.ErrDownloadTokenChannelRequired):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}
