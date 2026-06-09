package report

import (
	"context"
	"encoding/json"
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const defaultMaxBodyBytes int64 = 262144

func IngestReport(c *gin.Context, repository db.AppRepository, rdb *redis.Client) {
	keyValue, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid report key"})
		return
	}

	deviceID := strings.TrimSpace(c.GetHeader("X-Device-ID"))
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing X-Device-ID"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	reportCtx, err := repository.GetReportContextByKey(ctx, keyValue)
	if err != nil {
		if errors.Is(err, db.ErrReportKeyNotFound) {
			logrus.Debug("Report ingest rejected: unknown report key")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid report key"})
			return
		}
		logrus.Errorf("Failed to resolve report key context: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if !reportCtx.ReportsEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "reports are disabled for this app"})
		return
	}

	maxBodyBytes := viper.GetInt64("REPORTS_MAX_BODY_BYTES")
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req model.ReportIngestRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if status, msg := validateIngestRequest(&req, reportCtx.AppName); status != 0 {
		c.JSON(status, gin.H{"error": msg})
		return
	}

	hash := buildGroupHash(req.Application, req.System, req.Event)

	if !checkRateLimits(ctx, rdb, keyValue, deviceID, hash, time.Now()) {
		logrus.Debugf("Report ingest rate-limited: app=%s group=%s device=%s", reportCtx.AppName, hash, deviceID)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
		return
	}

	if err := repository.IncrementReportGroup(ctx, reportCtx.AppID, reportCtx.Owner, hash, req.Application, req.System, req.Event, time.Now()); err != nil {
		logrus.Errorf("Failed to upsert report group: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	logrus.Debugf("Report group counted: app=%s event=%s/%s group=%s", reportCtx.AppName, req.Event.Type, req.Event.Reason, hash)

	storedDetails := false
	if req.Details != nil {
		maxCompressed := viper.GetInt64("REPORTS_MAX_DETAILS_COMPRESSED_BYTES")
		if maxCompressed <= 0 {
			maxCompressed = defaultMaxDetailsCompressed
		}
		maxDecompressed := viper.GetInt64("REPORTS_MAX_DETAILS_DECOMPRESSED_BYTES")
		if maxDecompressed <= 0 {
			maxDecompressed = defaultMaxDetailsDecompressed
		}

		// Base count already incremented above; bad details are rejected without
		// undoing it.
		dd, status, msg := decodeAndValidateDetails(req.Details, maxCompressed, maxDecompressed)
		if status != 0 {
			logrus.Debugf("Report details rejected (validation): app=%s group=%s status=%d msg=%q", reportCtx.AppName, hash, status, msg)
			if err := repository.IncrementReportGroupDetails(ctx, reportCtx.AppID, hash, 0, 1, time.Now()); err != nil {
				logrus.Errorf("Failed to record rejected details: %v", err)
			}
			c.JSON(status, gin.H{"error": msg})
			return
		}

		now := time.Now()
		if storeDetailsBlob(ctx, repository, reportCtx.AppID, reportCtx.Owner, hash, req.Application, req.System, req.Event, dd, now) {
			storedDetails = true
			logrus.Debugf("Report details stored: app=%s group=%s decompressed=%d", reportCtx.AppName, hash, dd.decompressedSize)
			if err := repository.IncrementReportGroupDetails(ctx, reportCtx.AppID, hash, 1, 0, now); err != nil {
				logrus.Errorf("Failed to record stored details: %v", err)
			}
		} else if err := repository.IncrementReportGroupDetails(ctx, reportCtx.AppID, hash, 0, 1, now); err != nil {
			logrus.Errorf("Failed to record rejected details: %v", err)
		}
	}

	c.JSON(http.StatusAccepted, model.ReportIngestResponse{
		Status:        "accepted",
		GroupHash:     hash,
		StoredDetails: storedDetails,
	})
}

// validateIngestRequest returns (0, "") when valid, otherwise an HTTP status and
// a client-safe message. Version syntax is checked but not required to exist in
// release metadata.
func validateIngestRequest(req *model.ReportIngestRequest, keyAppName string) (int, string) {
	switch {
	case req.Application.Name == "":
		return http.StatusBadRequest, "missing application.name"
	case req.Application.Version == "":
		return http.StatusBadRequest, "missing application.version"
	case req.Application.Channel == "":
		return http.StatusBadRequest, "missing application.channel"
	case req.System.Platform == "":
		return http.StatusBadRequest, "missing system.platform"
	case req.System.Arch == "":
		return http.StatusBadRequest, "missing system.arch"
	case req.Event.Type == "":
		return http.StatusBadRequest, "missing event.type"
	case req.Event.Reason == "":
		return http.StatusBadRequest, "missing event.reason"
	}

	if !utils.IsValidAppName(req.Application.Name) {
		return http.StatusBadRequest, "invalid application.name"
	}
	if !utils.IsValidVersion(req.Application.Version) {
		return http.StatusBadRequest, "invalid application.version"
	}
	if !utils.IsValidChannelName(req.Application.Channel) {
		return http.StatusBadRequest, "invalid application.channel"
	}
	if !utils.IsValidPlatformName(req.System.Platform) {
		return http.StatusBadRequest, "invalid system.platform"
	}
	if !utils.IsValidArchName(req.System.Arch) {
		return http.StatusBadRequest, "invalid system.arch"
	}
	if !utils.IsValidEventType(req.Event.Type) {
		return http.StatusBadRequest, "invalid event.type"
	}
	if !utils.IsValidEventReason(req.Event.Reason) {
		return http.StatusBadRequest, "invalid event.reason"
	}

	if req.Application.Name != keyAppName {
		return http.StatusForbidden, "report key does not belong to this application"
	}

	return 0, ""
}

func bearerToken(c *gin.Context) (string, bool) {
	authHeader := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(authHeader[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
