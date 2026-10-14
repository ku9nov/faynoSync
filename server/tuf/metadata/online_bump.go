package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	tuf_storage "faynoSync/server/tuf/storage"
)

// Same defaults as RSTUF's bump_online_roles: check every 5 minutes, re-sign
// anything that expires within the next hour.
const (
	onlineBumpInterval  = 5 * time.Minute
	onlineBumpThreshold = time.Hour
	onlineBumpTickKey   = "TUF_ONLINE_BUMP_TICK"
)

func StartOnlineRolesBumper(ctx context.Context, mongoDatabase *mongo.Database, redisClient *redis.Client) {
	go func() {
		ticker := time.NewTicker(onlineBumpInterval)
		defer ticker.Stop()
		for {
			runOnlineBumpTick(ctx, mongoDatabase, redisClient)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func runOnlineBumpTick(ctx context.Context, mongoDatabase *mongo.Database, redisClient *redis.Client) {
	acquired, err := acquireOnlineBumpTick(ctx, redisClient)
	if err != nil {
		logrus.Errorf("TUF online bump: failed to acquire tick lock: %v", err)
		return
	}
	if !acquired {
		logrus.Debugf("TUF online bump: tick already handled within the last interval (key %s), next check in %s", onlineBumpTickKey, onlineBumpInterval)
		return
	}

	apps, err := listApps(ctx, mongoDatabase)
	if err != nil {
		logrus.Errorf("TUF online bump: failed to list apps: %v", err)
		return
	}
	logrus.Debugf("TUF online bump: checking %d apps", len(apps))

	for _, app := range apps {
		bumpExpiringOnlineRoles(ctx, redisClient, app, time.Now().UTC().Add(onlineBumpThreshold))
	}
}

// Not released on purpose: the TTL makes one replica own the whole interval.
func acquireOnlineBumpTick(ctx context.Context, redisClient *redis.Client) (bool, error) {
	return redisClient.SetNX(ctx, onlineBumpTickKey, time.Now().UTC().Format(time.RFC3339), onlineBumpInterval-30*time.Second).Result()
}

type bumpApp struct {
	AppName string `bson:"app_name"`
	Owner   string `bson:"owner"`
	Tuf     bool   `bson:"tuf"`
}

// All apps, not only tuf:true: publishing to TUF does not check the app's tuf
// flag, so a completed bootstrap in Redis is what says the app has metadata.
func listApps(ctx context.Context, mongoDatabase *mongo.Database) ([]bumpApp, error) {
	cursor, err := mongoDatabase.Collection("apps_meta").Find(
		ctx,
		bson.M{"app_name": bson.M{"$exists": true}},
		options.Find().SetProjection(bson.M{"app_name": 1, "owner": 1, "tuf": 1}),
	)
	if err != nil {
		return nil, err
	}
	var apps []bumpApp
	if err := cursor.All(ctx, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}

func bumpExpiringOnlineRoles(ctx context.Context, redisClient *redis.Client, app bumpApp, deadline time.Time) {
	adminName, appName := app.Owner, app.AppName
	keySuffix := adminName + "_" + appName

	state, completed, err := bootstrapState(ctx, redisClient, keySuffix)
	if err != nil {
		logrus.Errorf("TUF online bump %s/%s: failed to read bootstrap state: %v", adminName, appName, err)
		return
	}
	if state == "" {
		if !app.Tuf {
			logrus.Debugf("TUF online bump %s/%s: no bootstrap state (key %s) and TUF disabled, skipping", adminName, appName, "BOOTSTRAP_"+keySuffix)
			return
		}
		// The app is marked TUF but Redis has no bootstrap state (e.g. Redis lost
		// its data): nothing re-signs this app until recovery, so its timestamp
		// will expire and clients will reject the repository.
		logrus.Warnf("TUF online bump %s/%s: app has TUF enabled but no bootstrap state in Redis (key %s); run bootstrap recovery (POST /tuf/v1/bootstrap/recovery), skipping", adminName, appName, "BOOTSTRAP_"+keySuffix)
		return
	}
	if !completed {
		logrus.Debugf("TUF online bump %s/%s: bootstrap not completed (%s), skipping", adminName, appName, state)
		return
	}

	targetsOnline, err := isTargetsOnline(ctx, redisClient, keySuffix)
	if err != nil {
		logrus.Errorf("TUF online bump %s/%s: failed to read targets online flag: %v", adminName, appName, err)
		return
	}

	roles, err := expiringOnlineRoles(ctx, adminName, appName, deadline, targetsOnline)
	if err != nil {
		logrus.Errorf("TUF online bump %s/%s: failed to read metadata expiry: %v", adminName, appName, err)
		return
	}
	if len(roles) == 0 {
		logrus.Debugf("TUF online bump %s/%s: nothing expires before %s", adminName, appName, deadline.Format(time.RFC3339))
		return
	}

	logrus.Infof("TUF online bump %s/%s: re-signing roles expiring before %s: %v", adminName, appName, deadline.Format(time.RFC3339), roles)
	if _, err := forceOnlineMetadataUpdate(ctx, redisClient, adminName, appName, roles); err != nil {
		logrus.Errorf("TUF online bump %s/%s: failed to re-sign %v: %v", adminName, appName, roles, err)

		// A broken targets/delegated bump must not keep timestamp from being
		// refreshed: an expired timestamp blocks every client of the app.
		fallback := filterRoles(roles, "snapshot", "timestamp")
		if len(fallback) == 0 || len(fallback) == len(roles) {
			return
		}
		logrus.Infof("TUF online bump %s/%s: retrying with %v only", adminName, appName, fallback)
		if _, err := forceOnlineMetadataUpdate(ctx, redisClient, adminName, appName, fallback); err != nil {
			logrus.Errorf("TUF online bump %s/%s: failed to re-sign %v: %v", adminName, appName, fallback, err)
		}
	}
}

// An empty state means the key is missing; "pre-"/"signing-" mean bootstrap is in progress.
func bootstrapState(ctx context.Context, redisClient *redis.Client, keySuffix string) (string, bool, error) {
	value, err := redisClient.Get(ctx, "BOOTSTRAP_"+keySuffix).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, value != "" && !strings.HasPrefix(value, "pre-") && !strings.HasPrefix(value, "signing-"), nil
}

func isTargetsOnline(ctx context.Context, redisClient *redis.Client, keySuffix string) (bool, error) {
	value, err := redisClient.Get(ctx, "TARGETS_ONLINE_KEY_"+keySuffix).Result()
	if err == redis.Nil {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(value, "true") || value == "1", nil
}

type signedHeader struct {
	Signed struct {
		Expires time.Time `json:"expires"`
		Meta    map[string]struct {
			Version int64 `json:"version"`
		} `json:"meta"`
	} `json:"signed"`
}

// Walks the chain clients follow (timestamp -> snapshot -> roles it binds), so
// expiry is judged on exactly the versions clients will verify. Signatures are
// not checked here: this only decides what to bump, and the bump path verifies.
func expiringOnlineRoles(ctx context.Context, adminName, appName string, deadline time.Time, targetsOnline bool) ([]string, error) {
	tmpDir, err := os.MkdirTemp("", "tmp-tuf-bump-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	timestamp, err := readSignedHeader(ctx, adminName, appName, "timestamp.json", tmpDir)
	if err != nil {
		return nil, err
	}
	snapshotMeta, ok := timestamp.Signed.Meta["snapshot.json"]
	if !ok {
		return nil, fmt.Errorf("timestamp does not reference snapshot.json")
	}
	snapshot, err := readSignedHeader(ctx, adminName, appName, fmt.Sprintf("%d.snapshot.json", snapshotMeta.Version), tmpDir)
	if err != nil {
		return nil, err
	}

	var roles []string
	for name, meta := range snapshot.Signed.Meta {
		role := strings.TrimSuffix(name, ".json")
		// The snapshot is not verified yet and the name becomes a local file path.
		if !IsSafeRoleName(role) {
			return nil, fmt.Errorf("snapshot v%d references invalid role name %q", snapshotMeta.Version, name)
		}
		header, err := readSignedHeader(ctx, adminName, appName, fmt.Sprintf("%d.%s", meta.Version, name), tmpDir)
		if err != nil {
			return nil, err
		}
		if !header.Signed.Expires.Before(deadline) {
			continue
		}
		if role == "targets" && !targetsOnline {
			logrus.Warnf("TUF online bump %s/%s: targets uses an offline key and expires at %s; it must be re-signed through the signing flow", adminName, appName, header.Signed.Expires.Format(time.RFC3339))
			continue
		}
		roles = append(roles, role)
	}
	if snapshot.Signed.Expires.Before(deadline) {
		roles = append(roles, "snapshot")
	}
	if timestamp.Signed.Expires.Before(deadline) {
		roles = append(roles, "timestamp")
	}
	return roles, nil
}

func IsSafeRoleName(role string) bool {
	return role != "" && !strings.ContainsAny(role, `/\`) && !strings.Contains(role, "..")
}

// Delegated role files are stored as N.<name>.json next to the top-level ones,
// so a delegation named after a top-level role would overwrite its files. Case is
// ignored because signing state is keyed in Redis by the upper-cased role name.
func IsValidDelegatedRoleName(role string) bool {
	switch strings.ToLower(role) {
	case "root", "targets", "snapshot", "timestamp":
		return false
	}
	return IsSafeRoleName(role)
}

func readSignedHeader(ctx context.Context, adminName, appName, filename, tmpDir string) (*signedHeader, error) {
	path := filepath.Join(tmpDir, filename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, path); err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", filename, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filename, err)
	}
	var header signedHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filename, err)
	}
	return &header, nil
}

func filterRoles(roles []string, keep ...string) []string {
	var out []string
	for _, role := range roles {
		if contains(keep, role) {
			out = append(out, role)
		}
	}
	return out
}
