package report

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const presignedBlobTTL = 15 * time.Minute

type reportBlobResponse struct {
	model.ReportBlob
	URL string `json:"url"`
}

func ListReportGroups(c *gin.Context, repository db.AppRepository) {
	requester, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64)

	filters := map[string]string{}
	for _, k := range []string{"app", "version", "channel", "platform", "arch", "type", "reason", "from", "to"} {
		if v := c.Query(k); v != "" {
			filters[k] = v
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	groups, err := repository.GetReportGroups(ctx, requester, filters, page, limit)
	if err != nil {
		logrus.Errorf("Failed to list report groups: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	logrus.Debugf("Listed report groups: requester=%s returned=%d total=%d", requester, len(groups.Items), groups.Total)
	c.JSON(http.StatusOK, groups)
}

func ListReportGroupBlobs(c *gin.Context, repository db.AppRepository) {
	requester, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	groupHash := c.Param("groupHash")
	if !utils.IsValidGroupHash(groupHash) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid group hash"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	blobs, err := repository.GetReportBlobsByGroupHash(ctx, requester, groupHash, 0)
	if err != nil {
		logrus.Errorf("Failed to list report blobs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	bucket := viper.GetString("S3_BUCKET_NAME_PRIVATE")
	storageClient, err := utils.NewStorageFactory(viper.GetViper()).CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for report blobs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	items := make([]reportBlobResponse, 0, len(blobs))
	for _, b := range blobs {
		url, err := storageClient.GeneratePresignedURL(ctx, bucket, b.Storage.Key, presignedBlobTTL)
		if err != nil {
			logrus.Errorf("Failed to presign report blob %s: %v", b.Storage.Key, err)
			continue
		}
		items = append(items, reportBlobResponse{ReportBlob: *b, URL: url})
	}

	logrus.Debugf("Listed report blobs: requester=%s group=%s returned=%d", requester, groupHash, len(items))
	c.JSON(http.StatusOK, gin.H{"items": items})
}
