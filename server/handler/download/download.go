package download

import (
	"context"
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func DownloadArtifact(c *gin.Context, repository db.AppRepository) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	key := c.Query("key")
	artifact, err := repository.FindPrivateArtifact(ctx, key)
	if err != nil {
		if errors.Is(err, db.ErrPrivateArtifactNotFound) {
			respondNotFound(c)
			return
		}
		logrus.Errorf("Failed to resolve private artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve artifact"})
		return
	}

	respondWithJSON, allowed, err := authorizeDownload(ctx, c, repository, artifact)
	if err != nil {
		logrus.Errorf("Failed to authorize download: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to authorize download"})
		return
	}
	// A denied request must be indistinguishable from an unknown key, otherwise anonymous callers can probe which keys exist.
	if !allowed {
		respondNotFound(c)
		return
	}

	urlStr, err := utils.GeneratePresignedURL(c, key, 15*time.Minute)
	if err != nil {
		logrus.Error("Failed to generate pre-signed URL: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate pre-signed URL"})
		return
	}
	logrus.Debugln("Generated download URL: ", urlStr)
	if respondWithJSON {
		c.JSON(http.StatusOK, gin.H{"download_url": urlStr})
	} else {
		c.Redirect(http.StatusFound, urlStr)
	}
}

func authorizeDownload(ctx context.Context, c *gin.Context, repository db.AppRepository, artifact *model.PrivateArtifact) (bool, bool, error) {
	if tokenString, ok := utils.BearerToken(c.GetHeader("Authorization")); ok {
		if username, err := utils.UsernameFromJWT(tokenString); err == nil {
			allowed, err := repository.CanDownloadPrivateArtifact(ctx, username, artifact)
			if err != nil {
				return false, false, err
			}
			if allowed {
				return true, true, nil
			}
		}
	}

	if artifact.DownloadMode == utils.DownloadModeUnlisted {
		return false, true, nil
	}

	if downloadToken := c.GetHeader(utils.DownloadTokenHeader); downloadToken != "" {
		allowed, err := repository.HasDownloadToken(ctx, downloadToken, artifact)
		if err != nil {
			return false, false, err
		}
		return false, allowed, nil
	}

	return false, false, nil
}

func respondNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"error": "Artifact not found"})
}
