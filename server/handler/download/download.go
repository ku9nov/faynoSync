package download

import (
	"context"
	"faynoSync/server/utils"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func DownloadArtifact(c *gin.Context) {
	_, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	urlStr, err := utils.GeneratePresignedURL(c, c.Query("key"), 15*time.Minute)
	if err != nil {
		logrus.Error("Failed to generate pre-signed URL: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate pre-signed URL"})
		return
	}
	logrus.Debugln("Generated download URL: ", urlStr)
	if os.Getenv("ENABLE_PRIVATE_APP_DOWNLOADING") == "true" {
		c.Redirect(http.StatusFound, urlStr)
	} else {
		c.JSON(http.StatusOK, gin.H{"download_url": urlStr})
	}
}
