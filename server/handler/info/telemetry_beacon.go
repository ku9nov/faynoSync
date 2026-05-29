package info

import (
	"net/http"
	"strconv"

	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

func TelemetryBeacon(c *gin.Context, rdb *redis.Client) {
	params := map[string]interface{}{
		"owner":    c.Query("owner"),
		"app_name": c.Query("app_name"),
		"version":  c.Query("version"),
		"channel":  c.Query("channel"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
	}
	deviceID := c.GetHeader("X-Device-ID")

	logrus.Debugf("Telemetry beacon received: params=%+v device_id_present=%t is_latest=%q", params, deviceID != "", c.Query("is_latest"))

	if deviceID == "" {
		logrus.Debug("Telemetry beacon rejected because X-Device-ID is missing")
		c.Status(http.StatusNoContent)
		return
	}

	if !validTelemetryBeaconParams(params) {
		logrus.Debugf("Telemetry beacon rejected because params are invalid: %+v", params)
		c.Status(http.StatusNoContent)
		return
	}

	idx := LoadTelemetryAllowList()
	if idx == nil {
		logrus.Debug("Telemetry beacon skipped because allow-list is not loaded")
		c.Status(http.StatusNoContent)
		return
	}

	owner := params["owner"].(string)
	appName := params["app_name"].(string)
	channel := params["channel"].(string)
	platform := params["platform"].(string)
	arch := params["arch"].(string)

	if !idx.Valid(owner, appName, channel, platform, arch) {
		logrus.Debugf("Telemetry beacon rejected by allow-list: owner=%s app=%s channel=%s platform=%s arch=%s", owner, appName, channel, platform, arch)
		c.Status(http.StatusNoContent)
		return
	}

	hasUpdate, hasLatestState := beaconHasUpdate(c.Query("is_latest"))
	if hasLatestState {
		logrus.Debugf("Telemetry beacon latest state parsed: is_latest=%t has_update=%t", !hasUpdate, hasUpdate)
	} else {
		logrus.Debug("Telemetry beacon latest state is missing or invalid; latest/outdated metrics will be skipped")
	}
	trackClientTelemetryWithLatest(c.Request.Context(), rdb, params, hasUpdate, hasLatestState, deviceID)
	c.Status(http.StatusNoContent)
}

func validTelemetryBeaconParams(params map[string]interface{}) bool {
	owner, _ := params["owner"].(string)
	appName, _ := params["app_name"].(string)
	version, _ := params["version"].(string)
	channel, _ := params["channel"].(string)
	platform, _ := params["platform"].(string)
	arch, _ := params["arch"].(string)

	if owner == "" || appName == "" || channel == "" || platform == "" || arch == "" {
		return false
	}
	if !utils.IsValidAppName(appName) || !utils.IsValidChannelName(channel) || !utils.IsValidPlatformName(platform) || !utils.IsValidArchName(arch) {
		return false
	}
	if version != "" && !utils.IsValidVersion(version) {
		return false
	}
	return true
}

func beaconHasUpdate(raw string) (bool, bool) {
	if raw == "" {
		return false, false
	}

	isLatest, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false
	}
	return !isLatest, true
}
