package info

import (
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters/velopack"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

const velopackFeedContentType = "application/json"

var emptyVelopackFeed = []byte(`{"Assets":[]}`)

func FindVelopackFeed(c *gin.Context, repository db.AppRepository, database *mongo.Database) {
	owner := c.Param("owner")
	app := c.Param("app")
	platform := c.Param("platform")
	arch := c.Param("arch")

	if fileName := strings.TrimPrefix(c.Param("feed"), "/"); strings.HasSuffix(fileName, ".nupkg") {
		link, err := resolveVelopackPackageLink(c.Request.Context(), database, owner, app, platform, arch, fileName)
		if err != nil {
			logrus.Debugf("velopack package lookup failed for %s/%s/%s/%s/%s: %v", owner, app, platform, arch, fileName, err)
			c.JSON(http.StatusNotFound, gin.H{"error": "velopack package not found"})
			return
		}
		c.Redirect(http.StatusFound, link)
		return
	}

	channel, ok := parseVelopackChannel(c.Param("feed"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid velopack feed path"})
		return
	}

	if id := c.Query("id"); id != "" && id != app {
		c.JSON(http.StatusNotFound, gin.H{"error": "feed id does not match app"})
		return
	}

	localVersion := c.Query("localVersion")

	releases, err := loadVelopackReleases(c.Request.Context(), database, owner, app, channel, platform, arch)
	if err != nil {
		logrus.Debugf("velopack feed load failed for %s/%s/%s/%s/%s: %v", owner, app, platform, arch, channel, err)
		c.Data(http.StatusOK, velopackFeedContentType, emptyVelopackFeed)
		return
	}

	if localVersion != "" {
		if latest := latestPublishedVersion(releases); latest != "" {
			intermediate, err := repository.RequiredIntermediateStep(c.Request.Context(), owner, app, channel, platform, arch, localVersion, latest)
			if err != nil {
				logrus.Debugf("velopack intermediate lookup failed: %v", err)
			} else if intermediate != "" {
				logrus.Debugf("velopack capping feed at intermediate version %s for localVersion %s", intermediate, localVersion)
				releases = velopack.CapAtVersion(releases, intermediate, velopack.CompareVersions)
			}
		}
	}

	feed, err := velopack.BuildFeed(app, releases)
	if err != nil {
		logrus.Debugf("velopack BuildFeed failed for %s/%s: %v", owner, app, err)
		c.Data(http.StatusOK, velopackFeedContentType, emptyVelopackFeed)
		return
	}

	c.Data(http.StatusOK, velopackFeedContentType, feed)
}

func parseVelopackChannel(feed string) (string, bool) {
	feed = strings.TrimPrefix(feed, "/")
	if !strings.HasPrefix(feed, "releases.") || !strings.HasSuffix(feed, ".json") {
		return "", false
	}
	channel := feed[len("releases.") : len(feed)-len(".json")]
	if channel == "" || !utils.IsValidChannelName(channel) {
		return "", false
	}
	return channel, true
}

func latestPublishedVersion(releases []velopack.Release) string {
	latest := ""
	for _, r := range releases {
		if !r.Published {
			continue
		}
		if latest == "" || velopack.CompareVersions(r.Version, latest) > 0 {
			latest = r.Version
		}
	}
	return latest
}
