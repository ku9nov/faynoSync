package info

import (
	"context"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type VersionUsage struct {
	Version     string `json:"version"`
	ClientCount int64  `json:"client_count"`
}

type PlatformUsage struct {
	Platform    string `json:"platform"`
	ClientCount int64  `json:"client_count"`
}

type ArchitectureUsage struct {
	Arch        string `json:"arch"`
	ClientCount int64  `json:"client_count"`
}

type ChannelUsage struct {
	Channel     string `json:"channel"`
	ClientCount int64  `json:"client_count"`
}

type TelemetrySummary struct {
	TotalRequests             int64 `json:"total_requests"`
	UniqueClients             int64 `json:"unique_clients"`
	ClientsUsingLatestVersion int64 `json:"clients_using_latest_version"`
	ClientsOutdated           int64 `json:"clients_outdated"`
	TotalApps                 int   `json:"total_active_apps"`
}

type TelemetryVersions struct {
	UsedVersionsCount int            `json:"used_versions_count"`
	KnownVersions     []string       `json:"known_versions"`
	Usage             []VersionUsage `json:"usage"`
}

type TelemetryResponse struct {
	Date          string              `json:"date"`
	Admin         string              `json:"admin"`
	Summary       TelemetrySummary    `json:"summary"`
	Versions      TelemetryVersions   `json:"versions"`
	Platforms     []PlatformUsage     `json:"platforms"`
	Architectures []ArchitectureUsage `json:"architectures"`
	Channels      []ChannelUsage      `json:"channels"`
}

// GetTelemetry handles requests for analytics data
func GetTelemetry(c *gin.Context, rdb *redis.Client) {
	if rdb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Redis is not available"})
		return
	}

	// Get username from JWT token
	admin, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Get date from query parameter or use today
	dateStr := c.Query("date")
	if dateStr == "" {
		dateStr = time.Now().UTC().Format("2006-01-02")
	}

	// Get filter parameters
	filterApps := strings.Split(c.Query("apps"), ",")
	filterChannels := strings.Split(c.Query("channels"), ",")
	filterPlatforms := strings.Split(c.Query("platforms"), ",")
	filterArchitectures := strings.Split(c.Query("architectures"), ",")

	// Clean empty values from filters
	filterApps = cleanEmptyStrings(filterApps)
	filterChannels = cleanEmptyStrings(filterChannels)
	filterPlatforms = cleanEmptyStrings(filterPlatforms)
	filterArchitectures = cleanEmptyStrings(filterArchitectures)

	ctx := c.Request.Context()
	response := TelemetryResponse{
		Date:  dateStr,
		Admin: admin,
	}

	// Get all keys for this admin
	pattern := fmt.Sprintf("stats:%s:*", admin)
	keys, err := rdb.Keys(ctx, pattern).Result()
	if err != nil {
		logrus.Errorf("Error getting keys: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch telemetry data"})
		return
	}

	// Process each app's data
	appStats := make(map[string]bool)
	processedKeys := make(map[string]bool)
	var totalRequests int64
	var uniqueClients int64
	var latestVersionClients int64
	var outdatedClients int64

	for _, key := range keys {
		parts := strings.Split(key, ":")
		if len(parts) < 3 {
			continue
		}
		appName := parts[2]

		// Skip if app filtering is enabled and this app is not in the filter
		if len(filterApps) > 0 && !contains(filterApps, appName) {
			continue
		}

		appStats[appName] = true

		// Get app statistics
		baseKey := fmt.Sprintf("stats:%s:%s", admin, appName)

		// Get total requests
		requestsKey := fmt.Sprintf("%s:requests:%s", baseKey, dateStr)
		if !processedKeys[requestsKey] {
			if count, err := rdb.Get(ctx, requestsKey).Int64(); err == nil {
				totalRequests += count
				logrus.Debugf("App %s requests count: %d, total: %d", appName, count, totalRequests)
			}
			processedKeys[requestsKey] = true
		}

		// Get unique clients count
		clientsKey := fmt.Sprintf("%s:unique_clients:%s", baseKey, dateStr)
		if !processedKeys[clientsKey] {
			if count, err := rdb.SCard(ctx, clientsKey).Result(); err == nil {
				uniqueClients += count
				logrus.Debugf("App %s unique clients count: %d, total: %d", appName, count, uniqueClients)
			}
			processedKeys[clientsKey] = true
		}

		// Get clients using latest version
		latestKey := fmt.Sprintf("%s:clients_using_latest_version:%s", baseKey, dateStr)
		if !processedKeys[latestKey] {
			if count, err := rdb.SCard(ctx, latestKey).Result(); err == nil {
				latestVersionClients += count
				logrus.Debugf("App %s latest version clients count: %d, total: %d", appName, count, latestVersionClients)
			}
			processedKeys[latestKey] = true
		}

		// Get outdated clients
		outdatedKey := fmt.Sprintf("%s:clients_outdated:%s", baseKey, dateStr)
		if !processedKeys[outdatedKey] {
			if count, err := rdb.SCard(ctx, outdatedKey).Result(); err == nil {
				outdatedClients += count
				logrus.Debugf("App %s outdated clients count: %d, total: %d", appName, count, outdatedClients)
			}
			processedKeys[outdatedKey] = true
		}

		// Aggregate other stats for this app
		aggregateAppStats(ctx, rdb, admin, appName, dateStr, &response, filterChannels, filterPlatforms, filterArchitectures, processedKeys)
	}

	// Set the aggregated summary
	response.Summary.TotalRequests = totalRequests
	response.Summary.UniqueClients = uniqueClients
	response.Summary.ClientsUsingLatestVersion = latestVersionClients
	response.Summary.ClientsOutdated = outdatedClients
	response.Summary.TotalApps = len(appStats)

	logrus.Debugf("Final summary: %+v", response.Summary)
	c.JSON(http.StatusOK, response)
}

func aggregateAppStats(ctx context.Context, rdb *redis.Client, admin, appName, dateStr string, response *TelemetryResponse, filterChannels, filterPlatforms, filterArchitectures []string, processedKeys map[string]bool) {
	baseKey := fmt.Sprintf("stats:%s:%s", admin, appName)

	// Get known versions
	knownVersionsKey := fmt.Sprintf("%s:known_versions", baseKey)
	if count, err := rdb.SCard(ctx, knownVersionsKey).Result(); err == nil {
		response.Versions.UsedVersionsCount = int(count)
	}
	knownVersions, err := rdb.SMembers(ctx, knownVersionsKey).Result()
	if err == nil {
		// Add new versions to the response
		for _, version := range knownVersions {
			if !contains(response.Versions.KnownVersions, version) {
				response.Versions.KnownVersions = append(response.Versions.KnownVersions, version)
			}
		}
	}

	// Get version usage
	for _, version := range response.Versions.KnownVersions {
		versionKey := fmt.Sprintf("%s:version_usage:%s:%s", baseKey, dateStr, version)
		if count, err := rdb.SCard(ctx, versionKey).Result(); err == nil {
			// Update or add version usage
			found := false
			for i, usage := range response.Versions.Usage {
				if usage.Version == version {
					// Only update if this is the first time we're seeing this version for this app
					if !processedKeys[versionKey] {
						response.Versions.Usage[i].ClientCount += count
						processedKeys[versionKey] = true
					}
					found = true
					break
				}
			}
			if !found {
				response.Versions.Usage = append(response.Versions.Usage, VersionUsage{
					Version:     version,
					ClientCount: count,
				})
				processedKeys[versionKey] = true
			}
		}
	}

	// Get platform usage
	platformPattern := fmt.Sprintf("%s:platforms:%s:*", baseKey, dateStr)
	platformKeys, err := rdb.Keys(ctx, platformPattern).Result()
	if err == nil {
		for _, key := range platformKeys {
			parts := strings.Split(key, ":")
			if len(parts) < 5 {
				continue
			}
			platform := parts[5]

			// Skip if platform filtering is enabled and this platform is not in the filter
			if len(filterPlatforms) > 0 && !contains(filterPlatforms, platform) {
				continue
			}

			if count, err := rdb.SCard(ctx, key).Result(); err == nil {
				// Update or add platform usage
				found := false
				for i, usage := range response.Platforms {
					if usage.Platform == platform {
						// Only update if this is the first time we're seeing this platform for this app
						if !processedKeys[key] {
							response.Platforms[i].ClientCount += count
							processedKeys[key] = true
						}
						found = true
						break
					}
				}
				if !found {
					response.Platforms = append(response.Platforms, PlatformUsage{
						Platform:    platform,
						ClientCount: count,
					})
					processedKeys[key] = true
				}
			}
		}
	}

	// Get architecture usage
	archPattern := fmt.Sprintf("%s:architectures:%s:*", baseKey, dateStr)
	archKeys, err := rdb.Keys(ctx, archPattern).Result()
	if err == nil {
		for _, key := range archKeys {
			parts := strings.Split(key, ":")
			if len(parts) < 5 {
				continue
			}
			arch := parts[5]

			// Skip if architecture filtering is enabled and this architecture is not in the filter
			if len(filterArchitectures) > 0 && !contains(filterArchitectures, arch) {
				continue
			}

			if count, err := rdb.SCard(ctx, key).Result(); err == nil {
				// Update or add architecture usage
				found := false
				for i, usage := range response.Architectures {
					if usage.Arch == arch {
						// Only update if this is the first time we're seeing this architecture for this app
						if !processedKeys[key] {
							response.Architectures[i].ClientCount += count
							processedKeys[key] = true
						}
						found = true
						break
					}
				}
				if !found {
					response.Architectures = append(response.Architectures, ArchitectureUsage{
						Arch:        arch,
						ClientCount: count,
					})
					processedKeys[key] = true
				}
			}
		}
	}

	// Get channel usage
	channelPattern := fmt.Sprintf("%s:channels:%s:*", baseKey, dateStr)
	channelKeys, err := rdb.Keys(ctx, channelPattern).Result()
	if err == nil {
		for _, key := range channelKeys {
			parts := strings.Split(key, ":")
			if len(parts) < 5 {
				continue
			}
			channel := parts[5]

			// Skip if channel filtering is enabled and this channel is not in the filter
			if len(filterChannels) > 0 && !contains(filterChannels, channel) {
				continue
			}

			if count, err := rdb.SCard(ctx, key).Result(); err == nil {
				// Update or add channel usage
				found := false
				for i, usage := range response.Channels {
					if usage.Channel == channel {
						// Only update if this is the first time we're seeing this channel for this app
						if !processedKeys[key] {
							response.Channels[i].ClientCount += count
							processedKeys[key] = true
						}
						found = true
						break
					}
				}
				if !found {
					response.Channels = append(response.Channels, ChannelUsage{
						Channel:     channel,
						ClientCount: count,
					})
					processedKeys[key] = true
				}
			}
		}
	}
}

func cleanEmptyStrings(slice []string) []string {
	var result []string
	for _, s := range slice {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
