package info

import (
	_ "embed"
	"encoding/json"
	"faynoSync/server/utils"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

//go:embed telemetry.lua
var telemetryScriptContent string

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

type DailyStats struct {
	Date                      string `json:"date"`
	TotalRequests             int64  `json:"total_requests"`
	UniqueClients             int64  `json:"unique_clients"`
	ClientsUsingLatestVersion int64  `json:"clients_using_latest_version"`
	ClientsOutdated           int64  `json:"clients_outdated"`
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
	DateRange     []string            `json:"date_range,omitempty"`
	Admin         string              `json:"admin"`
	Summary       TelemetrySummary    `json:"summary"`
	Versions      TelemetryVersions   `json:"versions"`
	Platforms     []PlatformUsage     `json:"platforms"`
	Architectures []ArchitectureUsage `json:"architectures"`
	Channels      []ChannelUsage      `json:"channels"`
	DailyStats    []DailyStats        `json:"daily_stats"`
}

var telemetryScript *redis.Script

func init() {
	telemetryScript = redis.NewScript(telemetryScriptContent)
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

	// Get date range parameters
	dateStr := c.Query("date")
	timeRange := c.Query("range") // "week" or "month"

	var dateRange []string
	if timeRange != "" {
		// Calculate date range based on the specified period
		endDate := time.Now().UTC()
		var startDate time.Time

		switch timeRange {
		case "week":
			startDate = endDate.AddDate(0, 0, -7)
		case "month":
			startDate = endDate.AddDate(0, 0, -30)
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid range parameter. Use 'week' or 'month'"})
			return
		}

		// Generate date range
		for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
			dateRange = append(dateRange, d.Format("2006-01-02"))
		}
		logrus.Debugf("Generated date range for %s: %v", timeRange, dateRange)
	} else if dateStr == "" {
		// If no date or range specified, use today
		dateStr = time.Now().UTC().Format("2006-01-02")
		dateRange = []string{dateStr}
	} else {
		dateRange = []string{dateStr}
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

	filterChannelsJSON, _ := json.Marshal(filterChannels)
	filterPlatformsJSON, _ := json.Marshal(filterPlatforms)
	filterArchitecturesJSON, _ := json.Marshal(filterArchitectures)
	dateRangeJSON, _ := json.Marshal(dateRange)

	logrus.Debugf("Sending date range to Lua script: %s", string(dateRangeJSON))

	debugMode := logrus.GetLevel() == logrus.DebugLevel

	var response TelemetryResponse
	response.Date = dateRange[0]
	response.DateRange = dateRange
	response.Admin = admin
	response.DailyStats = make([]DailyStats, 0)

	if len(filterApps) > 0 {
		// Process each app individually
		for _, app := range filterApps {
			logrus.Debugf("Processing app: %s", app)
			result, err := telemetryScript.Run(ctx, rdb, nil,
				admin,
				string(dateRangeJSON),
				app,
				string(filterChannelsJSON),
				string(filterPlatformsJSON),
				string(filterArchitecturesJSON),
				strconv.FormatBool(debugMode),
			).Result()

			if err != nil {
				logrus.Errorf("Error executing Lua script for app %s: %v", app, err)
				continue
			}

			var appResult map[string]interface{}
			if err := json.Unmarshal([]byte(result.(string)), &appResult); err != nil {
				logrus.Errorf("Error parsing Lua script result for app %s: %v", app, err)
				continue
			}

			logrus.Debugf("Parsed result for app %s: %v", app, appResult)

			mergeResults(&response, appResult)
		}
	} else {
		// Process all apps at once
		result, err := telemetryScript.Run(ctx, rdb, nil,
			admin,
			string(dateRangeJSON),
			"*",
			string(filterChannelsJSON),
			string(filterPlatformsJSON),
			string(filterArchitecturesJSON),
			strconv.FormatBool(debugMode),
		).Result()

		if err != nil {
			logrus.Errorf("Error executing Lua script: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch telemetry data"})
			return
		}

		var resultMap map[string]interface{}
		if err := json.Unmarshal([]byte(result.(string)), &resultMap); err != nil {
			logrus.Errorf("Error parsing Lua script result: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse telemetry data"})
			return
		}

		logrus.Debugf("Parsed result for all apps: %v", resultMap)

		mergeResults(&response, resultMap)
	}

	logrus.Debugf("Final response: %+v", response)

	c.JSON(http.StatusOK, response)
}

// Helper function to merge results from multiple apps
func mergeResults(response *TelemetryResponse, appResult map[string]interface{}) {
	logrus.Debugf("Merging results for app: %v", appResult)

	// Merge summary data
	response.Summary.TotalRequests += int64(appResult["total_requests"].(float64))
	response.Summary.UniqueClients += int64(appResult["unique_clients"].(float64))
	response.Summary.ClientsUsingLatestVersion += int64(appResult["clients_using_latest_version"].(float64))
	response.Summary.ClientsOutdated += int64(appResult["clients_outdated"].(float64))
	response.Summary.TotalApps = int(appResult["total_active_apps"].(float64))

	// Merge daily stats
	if dailyStats, ok := appResult["daily_stats"].([]interface{}); ok {
		logrus.Debugf("Found daily stats in app result: %v", dailyStats)

		for _, ds := range dailyStats {
			if dailyStat, ok := ds.(map[string]interface{}); ok {
				date := dailyStat["date"].(string)
				logrus.Debugf("Processing daily stats for date: %s", date)

				found := false

				// Try to find existing entry for this date
				for i, existing := range response.DailyStats {
					if existing.Date == date {
						logrus.Debugf("Found existing entry for date %s, updating values", date)
						response.DailyStats[i].TotalRequests += int64(dailyStat["total_requests"].(float64))
						response.DailyStats[i].UniqueClients += int64(dailyStat["unique_clients"].(float64))
						response.DailyStats[i].ClientsUsingLatestVersion += int64(dailyStat["clients_using_latest_version"].(float64))
						response.DailyStats[i].ClientsOutdated += int64(dailyStat["clients_outdated"].(float64))
						found = true
						break
					}
				}

				// If no existing entry found, create new one
				if !found {
					logrus.Debugf("Creating new entry for date %s", date)
					response.DailyStats = append(response.DailyStats, DailyStats{
						Date:                      date,
						TotalRequests:             int64(dailyStat["total_requests"].(float64)),
						UniqueClients:             int64(dailyStat["unique_clients"].(float64)),
						ClientsUsingLatestVersion: int64(dailyStat["clients_using_latest_version"].(float64)),
						ClientsOutdated:           int64(dailyStat["clients_outdated"].(float64)),
					})
				}
			}
		}
	} else {
		logrus.Warnf("No daily stats found in app result or invalid format")
	}

	// Merge versions data
	versions := appResult["versions"].(map[string]interface{})
	if knownVersions, ok := versions["known_versions"].([]interface{}); ok {
		for _, v := range knownVersions {
			if version, ok := v.(string); ok {
				if !contains(response.Versions.KnownVersions, version) {
					response.Versions.KnownVersions = append(response.Versions.KnownVersions, version)
				}
			}
		}
	}

	response.Versions.UsedVersionsCount = int(versions["used_versions_count"].(float64))

	// Merge version usage
	if usage, ok := versions["usage"].([]interface{}); ok {
		for _, v := range usage {
			if usage, ok := v.(map[string]interface{}); ok {
				if version, ok := usage["version"].(string); ok {
					if count, ok := usage["client_count"].(float64); ok {
						found := false
						for i, existing := range response.Versions.Usage {
							if existing.Version == version {
								response.Versions.Usage[i].ClientCount += int64(count)
								found = true
								break
							}
						}
						if !found {
							response.Versions.Usage = append(response.Versions.Usage, VersionUsage{
								Version:     version,
								ClientCount: int64(count),
							})
						}
					}
				}
			}
		}
	}

	// Merge platforms
	if platforms, ok := appResult["platforms"].([]interface{}); ok {
		for _, p := range platforms {
			if platform, ok := p.(map[string]interface{}); ok {
				if name, ok := platform["platform"].(string); ok {
					if count, ok := platform["client_count"].(float64); ok {
						found := false
						for i, existing := range response.Platforms {
							if existing.Platform == name {
								response.Platforms[i].ClientCount += int64(count)
								found = true
								break
							}
						}
						if !found {
							response.Platforms = append(response.Platforms, PlatformUsage{
								Platform:    name,
								ClientCount: int64(count),
							})
						}
					}
				}
			}
		}
	}

	// Merge architectures
	if architectures, ok := appResult["architectures"].([]interface{}); ok {
		for _, a := range architectures {
			if arch, ok := a.(map[string]interface{}); ok {
				if name, ok := arch["platform"].(string); ok {
					if count, ok := arch["client_count"].(float64); ok {
						found := false
						for i, existing := range response.Architectures {
							if existing.Arch == name {
								response.Architectures[i].ClientCount += int64(count)
								found = true
								break
							}
						}
						if !found {
							response.Architectures = append(response.Architectures, ArchitectureUsage{
								Arch:        name,
								ClientCount: int64(count),
							})
						}
					}
				}
			}
		}
	}

	// Merge channels
	if channels, ok := appResult["channels"].([]interface{}); ok {
		for _, ch := range channels {
			if channel, ok := ch.(map[string]interface{}); ok {
				if name, ok := channel["platform"].(string); ok {
					if count, ok := channel["client_count"].(float64); ok {
						found := false
						for i, existing := range response.Channels {
							if existing.Channel == name {
								response.Channels[i].ClientCount += int64(count)
								found = true
								break
							}
						}
						if !found {
							response.Channels = append(response.Channels, ChannelUsage{
								Channel:     name,
								ClientCount: int64(count),
							})
						}
					}
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
