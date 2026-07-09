package report

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	maxReportGroupTags    = 20
	maxReportGroupNoteLen = 2000
)

var validReportGroupTag = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func isValidReportGroupStatus(status string) bool {
	switch status {
	case model.ReportGroupStatusOpen, model.ReportGroupStatusResolved, model.ReportGroupStatusMuted:
		return true
	}
	return false
}

func validateReportGroupTags(tags []string) bool {
	if len(tags) > maxReportGroupTags {
		return false
	}
	for _, tag := range tags {
		if !validReportGroupTag.MatchString(tag) {
			return false
		}
	}
	return true
}

func UpdateReportGroup(c *gin.Context, repository db.AppRepository) {
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

	var req model.UpdateReportGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Status == nil && req.Tags == nil && req.Note == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}
	if req.Status != nil && !isValidReportGroupStatus(*req.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	if req.Tags != nil && !validateReportGroupTags(*req.Tags) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tags"})
		return
	}
	if req.Note != nil && len(*req.Note) > maxReportGroupNoteLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": "note too long"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	found, err := repository.UpdateReportGroup(ctx, requester, groupHash, req.Status, req.Tags, req.Note, requester, time.Now())
	if err != nil {
		logrus.Errorf("Failed to update report group: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "report group not found"})
		return
	}

	logrus.Debugf("Report group updated: requester=%s group=%s status=%v tags=%v note=%v", requester, groupHash, req.Status, req.Tags, req.Note != nil)
	c.JSON(http.StatusOK, gin.H{"group_hash": groupHash, "updated": true})
}

func DeleteReportGroup(c *gin.Context, repository db.AppRepository) {
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

	deleted, keys, err := repository.DeleteReportGroup(ctx, requester, groupHash)
	if err != nil {
		logrus.Errorf("Failed to delete report group: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if !deleted {
		c.JSON(http.StatusNotFound, gin.H{"error": "report group not found"})
		return
	}

	if len(keys) > 0 {
		bucket := viper.GetString("S3_BUCKET_NAME_PRIVATE")
		storageClient, err := utils.NewStorageFactory(viper.GetViper()).CreateStorageClient()
		if err != nil {
			logrus.Errorf("Failed to create storage client to delete report blobs for group %s: %v", groupHash, err)
		} else if err := storageClient.DeleteObjects(ctx, bucket, keys); err != nil {
			logrus.Errorf("Failed to delete report blob objects for group %s (relying on lifecycle/TTL): %v", groupHash, err)
		}
	}

	logrus.Debugf("Report group deleted: requester=%s group=%s blobs=%d", requester, groupHash, len(keys))
	c.JSON(http.StatusOK, gin.H{"group_hash": groupHash, "deleted": true})
}
