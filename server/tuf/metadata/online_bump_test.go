package metadata

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tuf_storage "faynoSync/server/tuf/storage"
)

func signedJSON(expires time.Time, meta map[string]int64) []byte {
	metaJSON := "{"
	first := true
	for name, version := range meta {
		if !first {
			metaJSON += ","
		}
		first = false
		metaJSON += fmt.Sprintf(`%q:{"version":%d}`, name, version)
	}
	metaJSON += "}"
	return []byte(fmt.Sprintf(`{"signed":{"expires":%q,"meta":%s},"signatures":[]}`, expires.UTC().Format(time.RFC3339), metaJSON))
}

// serveMetadata serves files from mocked storage; keys are matched as "/<filename>".
func serveMetadata(t *testing.T, files map[string][]byte) {
	t.Helper()
	byKey := make(map[string][]byte, len(files))
	for name, body := range files {
		byKey["/"+name] = body
	}
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{client: &multiFileDownloadMockClient{files: byKey}}
	}
	t.Cleanup(func() {
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	})
}

// To verify: In expiringOnlineRoles drop the timestamp expiry check; test will fail (timestamp not selected).
func TestExpiringOnlineRoles_OnlyTimestampNearExpiry(t *testing.T) {
	now := time.Now().UTC()
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(30*time.Minute), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(7*24*time.Hour), map[string]int64{"targets.json": 3, "default.json": 2}),
		"3.targets.json":  signedJSON(now.Add(365*24*time.Hour), nil),
		"2.default.json":  signedJSON(now.Add(90*24*time.Hour), nil),
	})

	roles, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), true)

	require.NoError(t, err)
	assert.Equal(t, []string{"timestamp"}, roles)
}

// To verify: In expiringOnlineRoles compare with After instead of Before; test will fail (fresh roles selected).
func TestExpiringOnlineRoles_AllFresh_NothingToBump(t *testing.T) {
	now := time.Now().UTC()
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(20*time.Hour), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(7*24*time.Hour), map[string]int64{"targets.json": 3}),
		"3.targets.json":  signedJSON(now.Add(365*24*time.Hour), nil),
	})

	roles, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), true)

	require.NoError(t, err)
	assert.Empty(t, roles)
}

// Already-expired metadata (server was down past expiry) must be bumped too.
// To verify: In expiringOnlineRoles skip roles that are already expired; test will fail.
func TestExpiringOnlineRoles_AlreadyExpired_Selected(t *testing.T) {
	now := time.Now().UTC()
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(-48*time.Hour), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(-24*time.Hour), map[string]int64{"targets.json": 3}),
		"3.targets.json":  signedJSON(now.Add(365*24*time.Hour), nil),
	})

	roles, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), true)

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"snapshot", "timestamp"}, roles)
}

// To verify: In expiringOnlineRoles remove the targetsOnline check; test will fail (offline targets selected).
func TestExpiringOnlineRoles_OfflineTargetsSkipped_DelegatedSelected(t *testing.T) {
	now := time.Now().UTC()
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(20*time.Hour), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(7*24*time.Hour), map[string]int64{"targets.json": 3, "default.json": 2}),
		"3.targets.json":  signedJSON(now.Add(10*time.Minute), nil),
		"2.default.json":  signedJSON(now.Add(10*time.Minute), nil),
	})

	roles, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), false)

	require.NoError(t, err)
	assert.Equal(t, []string{"default"}, roles)
}

// Expiry must be judged on the versions snapshot binds, not on whatever is newest in storage.
// To verify: In expiringOnlineRoles read the latest stored role version instead of the snapshot-bound one; test will fail.
func TestExpiringOnlineRoles_ReadsSnapshotBoundVersions(t *testing.T) {
	now := time.Now().UTC()
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(20*time.Hour), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(7*24*time.Hour), map[string]int64{"default.json": 2}),
		"5.snapshot.json": signedJSON(now.Add(-time.Hour), map[string]int64{"default.json": 3}),
		"2.default.json":  signedJSON(now.Add(10*time.Minute), nil),
		"3.default.json":  signedJSON(now.Add(90*24*time.Hour), nil),
	})

	roles, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), true)

	require.NoError(t, err)
	assert.Equal(t, []string{"default"}, roles)
}

// To verify: In expiringOnlineRoles ignore download errors; test will fail (no error).
func TestExpiringOnlineRoles_MissingRoleFile_ReturnsError(t *testing.T) {
	now := time.Now().UTC()
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(20*time.Hour), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(7*24*time.Hour), map[string]int64{"targets.json": 3}),
	})

	_, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "3.targets.json")
}

// To verify: In bootstrapState accept "pre-"/"signing-" values; test will fail.
func TestBootstrapState(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	cases := map[string]bool{
		"":               false,
		"pre-task-1":     false,
		"signing-task-1": false,
		"task-1":         true,
		"<missing key>":  false,
	}
	for value, want := range cases {
		mr.FlushAll()
		if value != "<missing key>" {
			mr.Set("BOOTSTRAP_admin_app", value)
		}
		state, got, err := bootstrapState(ctx, redisClient, "admin_app")
		require.NoError(t, err)
		assert.Equal(t, want, got, "value %q", value)
		if value == "<missing key>" {
			assert.Empty(t, state)
		}
	}
}

// To verify: In isTargetsOnline default a missing key to false; test will fail.
func TestIsTargetsOnline(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	cases := map[string]bool{
		"<missing key>": true,
		"true":          true,
		"TRUE":          true,
		"1":             true,
		"false":         false,
		"0":             false,
	}
	for value, want := range cases {
		mr.FlushAll()
		if value != "<missing key>" {
			mr.Set("TARGETS_ONLINE_KEY_admin_app", value)
		}
		got, err := isTargetsOnline(ctx, redisClient, "admin_app")
		require.NoError(t, err)
		assert.Equal(t, want, got, "value %q", value)
	}
}

// To verify: In acquireOnlineBumpTick use SET instead of SETNX; test will fail (both replicas run the tick).
func TestAcquireOnlineBumpTick_OneReplicaPerInterval(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	first, err := acquireOnlineBumpTick(ctx, redisClient)
	require.NoError(t, err)
	second, err := acquireOnlineBumpTick(ctx, redisClient)
	require.NoError(t, err)

	assert.True(t, first)
	assert.False(t, second)

	mr.FastForward(onlineBumpInterval)
	third, err := acquireOnlineBumpTick(ctx, redisClient)
	require.NoError(t, err)
	assert.True(t, third, "next interval must be claimable")
}

// To verify: In bumpExpiringOnlineRoles skip the bootstrap check; test will fail (storage is accessed).
func TestBumpExpiringOnlineRoles_BootstrapIncomplete_NoStorageAccess(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.Set("BOOTSTRAP_admin_app", "pre-task-1")
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		t.Fatal("storage must not be accessed before bootstrap completes")
		return nil
	}
	t.Cleanup(func() { tuf_storage.StorageFactoryForDownload = savedFactory })

	bumpExpiringOnlineRoles(context.Background(), redisClient, bumpApp{AppName: "app", Owner: "admin", Tuf: true}, time.Now().Add(onlineBumpThreshold))

	assert.False(t, mr.Exists("LOCK_SNAPSHOT_admin_app"))
}

func TestFilterRoles(t *testing.T) {
	assert.Equal(t, []string{"snapshot", "timestamp"}, filterRoles([]string{"targets", "snapshot", "default", "timestamp"}, "snapshot", "timestamp"))
	assert.Empty(t, filterRoles([]string{"targets", "default"}, "snapshot", "timestamp"))
}

// The snapshot is read before any signature check and its role names become
// local paths, so a name with path components must not escape the temp dir.
// To verify: In expiringOnlineRoles remove the isSafeRoleName check; test will fail (file written outside the temp dir).
func TestExpiringOnlineRoles_PathTraversalRoleName_Refused(t *testing.T) {
	now := time.Now().UTC()
	escapeName := fmt.Sprintf("escape-%d.json", now.UnixNano())
	roleName := "x/../../" + escapeName
	serveMetadata(t, map[string][]byte{
		"timestamp.json":  signedJSON(now.Add(20*time.Hour), map[string]int64{"snapshot.json": 4}),
		"4.snapshot.json": signedJSON(now.Add(7*24*time.Hour), map[string]int64{roleName: 3}),
		"3." + roleName:   []byte("attacker content"),
	})
	escaped := filepath.Join(os.TempDir(), escapeName)
	t.Cleanup(func() { os.Remove(escaped) })

	_, err := expiringOnlineRoles(context.Background(), "admin", "app", now.Add(onlineBumpThreshold), true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role name")
	assert.NoFileExists(t, escaped)
}
