package bootstrap

import (
	"context"
	"strconv"
	"testing"

	"faynoSync/server/tuf/models"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validSaveSettingsPayload() *models.BootstrapPayload {
	return &models.BootstrapPayload{
		AppName: "myapp",
		Settings: models.Settings{
			Roles: models.RolesData{
				Root:      models.RoleExpiration{Expiration: 365},
				Targets:   models.RoleExpiration{Expiration: 90},
				Snapshot:  models.RoleExpiration{Expiration: 7},
				Timestamp: models.RoleExpiration{Expiration: 1},
			},
		},
		Metadata: map[string]models.RootMetadata{
			"root": {
				Signatures: []models.Signature{{KeyID: "k1", Sig: "s1"}},
				Signed: models.Signed{
					Roles: map[string]models.Role{
						"root": {KeyIDs: []string{"k1"}, Threshold: 1},
					},
				},
			},
		},
	}
}

// To verify: Remove the nil check for redisClient at line 14 in saveSettings; test will panic when calling redisClient.Set.
func TestSaveSettings_NilRedisClient_NoPanic(t *testing.T) {
	payload := validSaveSettingsPayload()
	saveSettings(nil, "admin", "myapp", payload)
	// No panic and no crash means the nil check worked
}

// To verify: Remove the check for payload.Metadata["root"] at lines 22–26 in saveSettings; test will panic when accessing payload.Settings.Roles after payload is invalid.
func TestSaveSettings_MissingRootMetadata_NoPanic(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	payload.Metadata = map[string]models.RootMetadata{"other": {}}

	saveSettings(client, "admin", "myapp", payload)

	// Root metadata was missing, so no keys should be written (function returns early)
	ctx := context.Background()
	err := client.Get(ctx, "ROOT_EXPIRATION_admin_myapp").Err()
	assert.Error(t, err, "ROOT_EXPIRATION should not be set when root metadata is missing")
}

// To verify: Change keySuffix to always use adminName only (ignore appName) in saveSettings; TestSaveSettings_Success_AdminAndApp will fail (wrong key suffix).
// To verify: Swap ROOT_EXPIRATION key construction; assertion on ROOT_EXPIRATION_<suffix> will fail.
func TestSaveSettings_Success_AdminOnly_KeysWritten(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	adminName := "admin"
	appName := ""

	t.Logf("Inputs: adminName=%q, appName=%q, rootExpiration=%d", adminName, appName, payload.Settings.Roles.Root.Expiration)

	saveSettings(client, adminName, appName, payload)

	ctx := context.Background()
	suffix := adminName

	// ROOT
	rootExp, err := client.Get(ctx, "ROOT_EXPIRATION_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "365", rootExp, "ROOT_EXPIRATION should match payload.Settings.Roles.Root.Expiration")

	rootThr, err := client.Get(ctx, "ROOT_THRESHOLD_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", rootThr)

	rootKeys, err := client.Get(ctx, "ROOT_NUM_KEYS_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", rootKeys, "ROOT_NUM_KEYS should equal len(rootMetadata.Signatures)")

	// TARGETS
	targetsExp, err := client.Get(ctx, "TARGETS_EXPIRATION_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "90", targetsExp)
	targetsThr, err := client.Get(ctx, "TARGETS_THRESHOLD_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", targetsThr)
	targetsKeys, err := client.Get(ctx, "TARGETS_NUM_KEYS_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", targetsKeys)
	onlineKey, err := client.Get(ctx, "TARGETS_ONLINE_KEY_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", onlineKey, "Redis stores true as \"1\" for Go int representation")

	// SNAPSHOT
	snapExp, err := client.Get(ctx, "SNAPSHOT_EXPIRATION_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "7", snapExp)
	snapThr, err := client.Get(ctx, "SNAPSHOT_THRESHOLD_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", snapThr)
	snapKeys, err := client.Get(ctx, "SNAPSHOT_NUM_KEYS_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", snapKeys)

	// TIMESTAMP
	tsExp, err := client.Get(ctx, "TIMESTAMP_EXPIRATION_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", tsExp)
	tsThr, err := client.Get(ctx, "TIMESTAMP_THRESHOLD_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", tsThr)
	tsKeys, err := client.Get(ctx, "TIMESTAMP_NUM_KEYS_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", tsKeys)

	t.Logf("Result: all keys for suffix %q written; ROOT_EXPIRATION=%s, ROOT_NUM_KEYS=%s", suffix, rootExp, rootKeys)
}

// To verify: Change keySuffix to not include appName when appName is non-empty; key ROOT_EXPIRATION_admin_myapp would be missing.
func TestSaveSettings_Success_AdminAndApp_KeySuffixIncludesApp(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	adminName := "admin"
	appName := "myapp"

	saveSettings(client, adminName, appName, payload)

	ctx := context.Background()
	suffix := adminName + "_" + appName

	val, err := client.Get(ctx, "ROOT_EXPIRATION_"+suffix).Result()
	require.NoError(t, err)
	assert.Equal(t, "365", val, "Key suffix must be admin_myapp when appName is set")

	err = client.Get(ctx, "ROOT_EXPIRATION_"+adminName).Err()
	assert.Error(t, err, "Key with admin-only suffix should not exist when appName is provided")
}

// To verify: Change rootThreshold to a constant 1 instead of reading from rootMetadata.Signed.Roles[\"root\"]; ROOT_THRESHOLD_ will be wrong.
func TestSaveSettings_RootThresholdFromMetadata(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	payload.Metadata["root"] = models.RootMetadata{
		Signatures: []models.Signature{{KeyID: "k1", Sig: "s1"}},
		Signed: models.Signed{
			Roles: map[string]models.Role{
				"root": {KeyIDs: []string{"k1"}, Threshold: 2},
			},
		},
	}

	saveSettings(client, "admin", "myapp", payload)

	ctx := context.Background()
	thr, err := client.Get(ctx, "ROOT_THRESHOLD_admin_myapp").Result()
	require.NoError(t, err)
	assert.Equal(t, "2", thr, "ROOT_THRESHOLD must come from rootMetadata.Signed.Roles[\"root\"].Threshold")
}

// To verify: Change rootNumKeys to a constant instead of len(rootMetadata.Signatures); ROOT_NUM_KEYS_ will not match signature count.
func TestSaveSettings_RootNumKeysFromSignatures(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	payload.Metadata["root"] = models.RootMetadata{
		Signatures: []models.Signature{
			{KeyID: "k1", Sig: "s1"},
			{KeyID: "k2", Sig: "s2"},
			{KeyID: "k3", Sig: "s3"},
		},
		Signed: models.Signed{
			Roles: map[string]models.Role{"root": {KeyIDs: []string{"k1", "k2", "k3"}, Threshold: 2}},
		},
	}

	saveSettings(client, "admin", "myapp", payload)

	ctx := context.Background()
	numKeys, err := client.Get(ctx, "ROOT_NUM_KEYS_admin_myapp").Result()
	require.NoError(t, err)
	assert.Equal(t, "3", numKeys, "ROOT_NUM_KEYS must equal len(rootMetadata.Signatures)")
}

// To verify: Use hardcoded 1 for targets/snapshot/timestamp threshold or num keys instead of rootMetadata.Signed.Roles; test will fail.
func TestSaveSettings_TargetsSnapshotTimestampFromRootRoles(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	payload.Metadata["root"] = models.RootMetadata{
		Signatures: []models.Signature{{KeyID: "k1", Sig: "s1"}},
		Signed: models.Signed{
			Roles: map[string]models.Role{
				"root":      {KeyIDs: []string{"k1"}, Threshold: 1},
				"targets":   {KeyIDs: []string{"t1", "t2"}, Threshold: 2},
				"snapshot":  {KeyIDs: []string{"s1"}, Threshold: 1},
				"timestamp": {KeyIDs: []string{"ts1", "ts2", "ts3"}, Threshold: 2},
			},
		},
	}

	saveSettings(client, "admin", "myapp", payload)

	ctx := context.Background()
	suffix := "admin_myapp"
	targetsThr, _ := client.Get(ctx, "TARGETS_THRESHOLD_"+suffix).Result()
	assert.Equal(t, "2", targetsThr, "TARGETS_THRESHOLD must come from root roles")
	targetsKeys, _ := client.Get(ctx, "TARGETS_NUM_KEYS_"+suffix).Result()
	assert.Equal(t, "2", targetsKeys, "TARGETS_NUM_KEYS must be len(KeyIDs)")
	snapThr, _ := client.Get(ctx, "SNAPSHOT_THRESHOLD_"+suffix).Result()
	assert.Equal(t, "1", snapThr, "SNAPSHOT_THRESHOLD must come from root roles")
	snapKeys, _ := client.Get(ctx, "SNAPSHOT_NUM_KEYS_"+suffix).Result()
	assert.Equal(t, "1", snapKeys, "SNAPSHOT_NUM_KEYS must be len(KeyIDs)")
	tsThr, _ := client.Get(ctx, "TIMESTAMP_THRESHOLD_"+suffix).Result()
	assert.Equal(t, "2", tsThr, "TIMESTAMP_THRESHOLD must come from root roles")
	tsKeys, _ := client.Get(ctx, "TIMESTAMP_NUM_KEYS_"+suffix).Result()
	assert.Equal(t, "3", tsKeys, "TIMESTAMP_NUM_KEYS must be len(KeyIDs)")
}

// To verify: Omit writing TARGETS_EXPIRATION or use wrong role; TARGETS_EXPIRATION_ value will be wrong.
func TestSaveSettings_AllRoleExpirationsWritten(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	payload.Settings.Roles.Root.Expiration = 400
	payload.Settings.Roles.Targets.Expiration = 120
	payload.Settings.Roles.Snapshot.Expiration = 14
	payload.Settings.Roles.Timestamp.Expiration = 2

	saveSettings(client, "a", "b", payload)

	ctx := context.Background()
	suffix := "a_b"
	expirations := map[string]string{
		"ROOT_EXPIRATION_" + suffix:      "400",
		"TARGETS_EXPIRATION_" + suffix:   "120",
		"SNAPSHOT_EXPIRATION_" + suffix:  "14",
		"TIMESTAMP_EXPIRATION_" + suffix: "2",
	}
	for key, expected := range expirations {
		val, err := client.Get(ctx, key).Result()
		require.NoError(t, err, "Key %s should be set", key)
		assert.Equal(t, expected, val, "Key %s value", key)
	}
}

// To verify: Use wrong default for rootThreshold when root role is missing (e.g. 0); ROOT_THRESHOLD_ should be 1.
func TestSaveSettings_EmptyRootRoles_DefaultThresholdOne(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := validSaveSettingsPayload()
	payload.Metadata["root"] = models.RootMetadata{
		Signatures: []models.Signature{{KeyID: "k1", Sig: "s1"}},
		Signed:     models.Signed{Roles: map[string]models.Role{}}, // no "root" role
	}

	saveSettings(client, "admin", "app", payload)

	ctx := context.Background()
	thr, err := client.Get(ctx, "ROOT_THRESHOLD_admin_app").Result()
	require.NoError(t, err)
	thrInt, _ := strconv.Atoi(thr)
	assert.Equal(t, 1, thrInt, "When root role is missing in Signed.Roles, rootThreshold must default to 1")
}
