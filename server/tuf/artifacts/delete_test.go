package artifacts

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
	tuf_utils "faynoSync/server/tuf/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

func makeRemoveArtifactsTestEnv(t *testing.T, adminName, appName string) (storeDir, keyDir string, cleanup func()) {
	t.Helper()
	rootTmp := t.TempDir()
	keyDir = t.TempDir()
	storeDir = t.TempDir()

	expires := time.Now().Add(365 * 24 * time.Hour)
	keys := map[string]ed25519.PrivateKey{}
	roles := repository.New()

	roles.SetRoot(tuf_metadata.Root(expires))
	roles.SetTargets("targets", tuf_metadata.Targets(expires))
	roles.SetSnapshot(tuf_metadata.Snapshot(expires))
	roles.SetTimestamp(tuf_metadata.Timestamp(expires))

	for _, name := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, private, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		keys[name] = private
		key, err := tuf_metadata.KeyFromPublicKey(private.Public())
		require.NoError(t, err)
		err = roles.Root().Signed.AddKey(key, name)
		require.NoError(t, err)
	}

	for _, name := range []string{"root", "targets", "snapshot", "timestamp"} {
		signer, err := signature.LoadSigner(keys[name], crypto.Hash(0))
		require.NoError(t, err)
		switch name {
		case "root":
			_, err = roles.Root().Sign(signer)
		case "targets":
			_, err = roles.Targets("targets").Sign(signer)
		case "snapshot":
			_, err = roles.Snapshot().Sign(signer)
		case "timestamp":
			_, err = roles.Timestamp().Sign(signer)
		}
		require.NoError(t, err)
	}

	rootPath := filepath.Join(rootTmp, "1.root.json")
	require.NoError(t, roles.Root().ToFile(rootPath, true))
	rootJSON, err := os.ReadFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))

	for _, name := range []string{"timestamp", "snapshot", "targets"} {
		role, ok := rootMeta.Signed.Roles[name]
		require.True(t, ok)
		require.NotEmpty(t, role.KeyIDs)
		keyID := role.KeyIDs[0]
		seed := keys[name].Seed()
		require.NoError(t, os.WriteFile(filepath.Join(keyDir, keyID), seed, 0600))
	}

	targetsKeyID := rootMeta.Signed.Roles["targets"].KeyIDs[0]
	targetsKey := roles.Root().Signed.Keys[targetsKeyID]
	require.NotNil(t, targetsKey)

	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{targetsKeyID: targetsKey},
		Roles: []tuf_metadata.DelegatedRole{{Name: "updates", KeyIDs: []string{targetsKeyID}, Threshold: 1, Paths: []string{"updates/*"}}},
	}
	roles.SetTargets("targets", targets)
	targetsSigner, err := signature.LoadSigner(keys["targets"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = roles.Targets("targets").Sign(targetsSigner)
	require.NoError(t, err)
	targetsPath := filepath.Join(rootTmp, "2.targets.json")
	require.NoError(t, roles.Targets("targets").ToFile(targetsPath, true))
	targetsJSON, err := os.ReadFile(targetsPath)
	require.NoError(t, err)

	// Delegation "updates" with one target for removal tests
	delegationExp := tuf_utils.HelperExpireIn(90)
	delegationTargets := tuf_metadata.Targets(delegationExp)
	delegationTargets.Signed.Targets = make(map[string]*tuf_metadata.TargetFiles)
	hashBytes, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	delegationTargets.Signed.Targets["updates/app-1.0.0.tar"] = &tuf_metadata.TargetFiles{
		Length: 1024,
		Hashes: tuf_metadata.Hashes{"sha256": tuf_metadata.HexBytes(hashBytes)},
	}
	delegationTargets.Signed.Version = 1
	roles.SetTargets("updates", delegationTargets)
	_, err = roles.Targets("updates").Sign(targetsSigner)
	require.NoError(t, err)
	updatesPath := filepath.Join(rootTmp, "1.updates.json")
	require.NoError(t, roles.Targets("updates").ToFile(updatesPath, true))
	updatesJSON, err := os.ReadFile(updatesPath)
	require.NoError(t, err)

	// Snapshot with meta for targets and updates
	snapExp := tuf_utils.HelperExpireIn(7)
	snapshot := tuf_metadata.Snapshot(snapExp)
	snapshot.Signed.Meta = map[string]*tuf_metadata.MetaFiles{
		"targets.json": tuf_metadata.MetaFile(2),
		"updates.json": tuf_metadata.MetaFile(1),
	}
	snapshot.Signed.Version = 1
	roles.SetSnapshot(snapshot)
	snapSigner, err := signature.LoadSigner(keys["snapshot"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = roles.Snapshot().Sign(snapSigner)
	require.NoError(t, err)
	snapPath := filepath.Join(rootTmp, "1.snapshot.json")
	require.NoError(t, roles.Snapshot().ToFile(snapPath, true))
	snapJSON, err := os.ReadFile(snapPath)
	require.NoError(t, err)

	// Timestamp with meta for snapshot
	tsExp := tuf_utils.HelperExpireIn(1)
	timestamp := tuf_metadata.Timestamp(tsExp)
	timestamp.Signed.Meta = map[string]*tuf_metadata.MetaFiles{
		"snapshot.json": tuf_metadata.MetaFile(1),
	}
	roles.SetTimestamp(timestamp)
	tsSigner, err := signature.LoadSigner(keys["timestamp"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = roles.Timestamp().Sign(tsSigner)
	require.NoError(t, err)
	tsPath := filepath.Join(rootTmp, "timestamp.json")
	require.NoError(t, roles.Timestamp().ToFile(tsPath, true))
	tsJSON, err := os.ReadFile(tsPath)
	require.NoError(t, err)

	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", adminName, appName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.root.json"), rootJSON, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "2.targets.json"), targetsJSON, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.updates.json"), updatesJSON, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.snapshot.json"), snapJSON, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "timestamp.json"), tsJSON, 0644))

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload

	client := &fsStorageClient{baseDir: storeDir}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")

	tuf_storage.ListMetadataForLatest = func(ctx context.Context, a, p, prefix string) ([]string, error) {
		if a != adminName || p != appName {
			return nil, fmt.Errorf("unexpected admin/app")
		}
		return []string{"1.root.json", "2.targets.json", "1.updates.json", "1.snapshot.json", "timestamp.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: client}
	}

	oldKeyDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)

	cleanup = func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
		viper.GetViper().Set("ONLINE_KEY_DIR", oldKeyDir)
	}
	return storeDir, keyDir, cleanup
}

// To verify: In RemoveArtifacts change the bootstrap key check (BOOTSTRAP_...) or the redis.Nil/empty handling; test will fail (no error or wrong message).
func TestRemoveArtifacts_BootstrapNotCompleted_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{}, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap not completed")
	t.Logf("Inputs: admin=%q app=%q; Result: err=%v", testAdminName, testAppName, err)
}

// To verify: In RemoveArtifacts remove the check for bootstrapValue == ""; test with empty value may pass incorrectly.
func TestRemoveArtifacts_BootstrapKeyEmpty_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "")

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{}, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap not completed")
}

// To verify: In RemoveArtifacts remove the "no valid artifacts to remove" check after filtering invalid paths; test will fail.
func TestRemoveArtifacts_NoValidArtifacts_ReturnsError(t *testing.T) {
	_, _, cleanup := makeRemoveArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	artifacts := []Artifact{
		{Path: "other/unknown.exe", Info: ArtifactInfo{Length: 100, Hashes: map[string]string{"sha256": "abc"}}},
	}

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid artifacts to remove")
	t.Logf("Inputs: artifacts=%v; Result: err=%v", artifacts, err)
}

// To verify: In RemoveArtifacts change error handling when DownloadMetadataFromS3 fails for root; test will fail (no error or wrong message).
func TestRemoveArtifacts_DownloadRootFails_ReturnsError(t *testing.T) {
	_, _, cleanup := makeRemoveArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	defer func() { tuf_storage.StorageFactoryForDownload = savedFactoryD }()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{
		{Path: "updates/x", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download root metadata")
}

// To verify: In RemoveArtifacts change error handling for FindLatestMetadataVersion (targets); test will fail (no error or wrong message).
func TestRemoveArtifacts_FindLatestTargetsFails_ReturnsError(t *testing.T) {
	_, _, cleanup := makeRemoveArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	artifacts := []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find latest targets version")
}

// To verify: In RemoveArtifacts skip loading timestamp private key error; test will fail (no error or wrong message).
func TestRemoveArtifacts_LoadTimestampKeyFails_ReturnsError(t *testing.T) {
	_, _, cleanup := makeRemoveArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()
	emptyKeyDir := t.TempDir()
	oldDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", emptyKeyDir)
	defer viper.GetViper().Set("ONLINE_KEY_DIR", oldDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{
		{Path: "updates/x", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load timestamp private key")
}

// To verify: In RemoveArtifacts change getRoleForArtifactPath or delegation path matching; test will fail (error or no removal).
func TestRemoveArtifacts_ValidArtifact_Removal_Success(t *testing.T) {
	storeDir, _, cleanup := makeRemoveArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")
	mr.Set("TARGETS_EXPIRATION_"+testAdminName+"_"+testAppName, "365")
	mr.Set("updates_EXPIRATION_"+testAdminName+"_"+testAppName, "90")
	mr.Set("SNAPSHOT_EXPIRATION_"+testAdminName+"_"+testAppName, "7")
	mr.Set("TIMESTAMP_EXPIRATION_"+testAdminName+"_"+testAppName, "1")

	artifacts := []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{Length: 1024, Hashes: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
	}

	err := RemoveArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, testTaskID)

	require.NoError(t, err)
	val, err := redisClient.Get(ctx, "task:"+testTaskID).Result()
	require.NoError(t, err)
	require.NotEmpty(t, val)
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	// After removal, delegation is re-uploaded as 2.updates.json (version incremented)
	require.FileExists(t, filepath.Join(metadataPrefix, "2.updates.json"), "delegation metadata should be updated after removal")
	t.Logf("Inputs: artifacts=%v; Result: success, task status saved", artifacts)
}

// To verify: When remove flow updates snapshot and timestamp (updateSnapshotAndTimestamp), existing timestamp version is incremented.
func TestUpdateSnapshotAndTimestamp_AfterRemove_TimestampVersionIncremented(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storeDir := t.TempDir()
	tmpDir := t.TempDir()
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))

	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	snap.Signed.Version = 1
	repo.SetSnapshot(snap)
	_, err := repo.Snapshot().Sign(snapSigner)
	require.NoError(t, err)
	snapshotPath := filepath.Join(metadataPrefix, "1.snapshot.json")
	require.NoError(t, repo.Snapshot().ToFile(snapshotPath, true))

	ts := tuf_metadata.Timestamp(exp)
	ts.Signed.Version = 3
	repo.SetTimestamp(ts)
	_, err = repo.Timestamp().Sign(tsSigner)
	require.NoError(t, err)
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	require.NoError(t, repo.Timestamp().ToFile(timestampPath, true))
	require.FileExists(t, timestampPath)

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	err = updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "timestamp.json"))
	require.NoError(t, err)
	var tsSigned struct {
		Signed struct {
			Version int `json:"version"`
		} `json:"signed"`
	}
	require.NoError(t, json.Unmarshal(data, &tsSigned))
	assert.Equal(t, 4, tsSigned.Signed.Version, "when remove flow updates snapshot and timestamp, existing timestamp (version 3) must be incremented to 4")
}

// --- removeArtifactsFromDelegatedRole tests ---

func makeRemoveArtifactsFromDelegatedRoleEnv(t *testing.T, adminName, appName string) (repo *repository.Type, storeDir, keyDir, tmpDir string, redisClient *redis.Client, cleanup func()) {
	t.Helper()
	keyDir = t.TempDir()
	storeDir = t.TempDir()
	tmpDir = t.TempDir()

	expires := time.Now().Add(365 * 24 * time.Hour)
	keys := map[string]ed25519.PrivateKey{}
	repo = repository.New()

	repo.SetRoot(tuf_metadata.Root(expires))
	repo.SetTargets("targets", tuf_metadata.Targets(expires))

	for _, name := range []string{"root", "targets"} {
		_, private, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		keys[name] = private
		key, err := tuf_metadata.KeyFromPublicKey(private.Public())
		require.NoError(t, err)
		err = repo.Root().Signed.AddKey(key, name)
		require.NoError(t, err)
	}

	targetsKeyID := repo.Root().Signed.Roles["targets"].KeyIDs[0]
	seed := keys["targets"].Seed()
	require.NoError(t, os.WriteFile(filepath.Join(keyDir, targetsKeyID), seed, 0600))

	targetsKey := repo.Root().Signed.Keys[targetsKeyID]
	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{targetsKeyID: targetsKey},
		Roles: []tuf_metadata.DelegatedRole{{Name: "updates", KeyIDs: []string{targetsKeyID}, Threshold: 1, Paths: []string{"updates/*"}}},
	}
	repo.SetTargets("targets", targets)

	delegationExp := tuf_utils.HelperExpireIn(90)
	delegationTargets := tuf_metadata.Targets(delegationExp)
	delegationTargets.Signed.Targets = make(map[string]*tuf_metadata.TargetFiles)
	hashBytes, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	delegationTargets.Signed.Targets["updates/app-1.0.0.tar"] = &tuf_metadata.TargetFiles{
		Length: 1024,
		Hashes: tuf_metadata.Hashes{"sha256": tuf_metadata.HexBytes(hashBytes)},
	}
	delegationTargets.Signed.Version = 1
	repo.SetTargets("updates", delegationTargets)
	targetsSigner, err := signature.LoadSigner(keys["targets"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = repo.Targets("updates").Sign(targetsSigner)
	require.NoError(t, err)
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", adminName, appName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))
	updatesPath := filepath.Join(metadataPrefix, "1.updates.json")
	require.NoError(t, repo.Targets("updates").ToFile(updatesPath, true))

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload

	client := &fsStorageClient{baseDir: storeDir}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.ListMetadataForLatest = func(ctx context.Context, a, p, prefix string) ([]string, error) {
		if a != adminName || p != appName {
			return nil, fmt.Errorf("unexpected admin/app")
		}
		return []string{"1.updates.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: client}
	}

	oldKeyDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)

	mr := miniredis.RunT(t)
	redisClient = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("updates_EXPIRATION_"+adminName+"_"+appName, "90")

	cleanup = func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
		viper.GetViper().Set("ONLINE_KEY_DIR", oldKeyDir)
		mr.Close()
	}
	return repo, storeDir, keyDir, tmpDir, redisClient, cleanup
}

// To verify: In removeArtifactsFromDelegatedRole change removal logic or signing; test will fail (removed=false or no 2.updates.json).
func TestRemoveArtifactsFromDelegatedRole_Success(t *testing.T) {
	repo, storeDir, _, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	artifacts := []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{Length: 1024, Hashes: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
	}

	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", artifacts, testAdminName, testAppName, redisClient, tmpDir)

	require.NoError(t, err)
	assert.True(t, removed)
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.FileExists(t, filepath.Join(metadataPrefix, "2.updates.json"))
	t.Logf("Inputs: role=updates artifacts=%v; Result: removed=true", artifacts)
}

// To verify: In removeArtifactsFromDelegatedRole skip FindLatestMetadataVersion error; test will fail (no error or wrong message).
func TestRemoveArtifactsFromDelegatedRole_FindLatestFails_ReturnsError(t *testing.T) {
	repo, _, _, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	ctx := context.Background()
	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", []Artifact{{Path: "updates/x", Info: ArtifactInfo{}}}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "failed to find latest delegation metadata for role updates")
}

// To verify: In removeArtifactsFromDelegatedRole skip DownloadMetadataFromS3 error; test will fail (no error or wrong message).
func TestRemoveArtifactsFromDelegatedRole_DownloadFails_ReturnsError(t *testing.T) {
	repo, _, _, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	defer func() { tuf_storage.StorageFactoryForDownload = savedFactoryD }()

	ctx := context.Background()
	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", []Artifact{{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{}}}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "failed to download updates metadata")
}

// To verify: In removeArtifactsFromDelegatedRole remove the "delegation has no targets" branch; test may not cover (false, nil).
func TestRemoveArtifactsFromDelegatedRole_DelegationHasNoTargets_ReturnsFalseNil(t *testing.T) {
	repo, storeDir, keyDir, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	// Overwrite 1.updates.json with delegation that has no targets (empty Signed.Targets)
	delegationExp := tuf_utils.HelperExpireIn(90)
	emptyTargets := tuf_metadata.Targets(delegationExp)
	emptyTargets.Signed.Targets = nil
	emptyTargets.Signed.Version = 1
	repo.SetTargets("updates", emptyTargets)
	targetsKeyID := repo.Root().Signed.Roles["targets"].KeyIDs[0]
	seed := loadKeyFromFile(t, filepath.Join(keyDir, targetsKeyID))
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)
	_, err = repo.Targets("updates").Sign(signer)
	require.NoError(t, err)
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.NoError(t, repo.Targets("updates").ToFile(filepath.Join(metadataPrefix, "1.updates.json"), true))

	ctx := context.Background()
	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", []Artifact{{Path: "updates/any", Info: ArtifactInfo{}}}, testAdminName, testAppName, redisClient, tmpDir)

	require.NoError(t, err)
	assert.False(t, removed)
	t.Logf("Delegation with no targets: removed=false, err=nil")
}

func loadKeyFromFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// To verify: In removeArtifactsFromDelegatedRole remove the removedCount==0 branch; test may not cover (false, nil).
func TestRemoveArtifactsFromDelegatedRole_ArtifactNotFound_ReturnsFalseNil(t *testing.T) {
	repo, _, _, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	artifacts := []Artifact{
		{Path: "updates/nonexistent.tar", Info: ArtifactInfo{}},
	}

	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", artifacts, testAdminName, testAppName, redisClient, tmpDir)

	require.NoError(t, err)
	assert.False(t, removed)
	t.Logf("Artifact not in delegation: removed=false, err=nil")
}

// To verify: In removeArtifactsFromDelegatedRole skip "not enough distinct keys" check for threshold; test will fail (no error or wrong message).
func TestRemoveArtifactsFromDelegatedRole_NotEnoughDistinctKeys_ReturnsError(t *testing.T) {
	repo, _, _, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	// Role has one key but threshold 2: signing will fail with "not enough distinct keys".
	for i := range repo.Targets("targets").Signed.Delegations.Roles {
		if repo.Targets("targets").Signed.Delegations.Roles[i].Name == "updates" {
			repo.Targets("targets").Signed.Delegations.Roles[i].Threshold = 2
			break
		}
	}

	ctx := context.Background()
	artifacts := []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{Length: 1024, Hashes: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
	}

	_, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", artifacts, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enough distinct keys for delegated role updates")
	assert.Contains(t, err.Error(), "need 2, got 1")
}

// To verify: In removeArtifactsFromDelegatedRole skip "no key IDs found" check; test will fail (no error or wrong message).
func TestRemoveArtifactsFromDelegatedRole_NoKeyIDsForRole_ReturnsError(t *testing.T) {
	repo, storeDir, keyDir, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	// Replace targets with delegations that have no role "updates" (empty Roles)
	targetsKeyID := repo.Root().Signed.Roles["targets"].KeyIDs[0]
	targetsKey := repo.Root().Signed.Keys[targetsKeyID]
	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{targetsKeyID: targetsKey},
		Roles: []tuf_metadata.DelegatedRole{}, // no "updates" role
	}
	repo.SetTargets("targets", targets)
	// Still have 1.updates.json in store so download/load succeed; then lookup roleKeyIDs fails
	_ = storeDir
	_ = keyDir

	ctx := context.Background()
	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "no key IDs found for delegated role updates")
}

// To verify: In removeArtifactsFromDelegatedRole skip LoadPrivateKeyFromFilesystem error; test will fail (no error or wrong message).
func TestRemoveArtifactsFromDelegatedRole_LoadDelegationKeyFails_ReturnsError(t *testing.T) {
	repo, _, keyDir, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	emptyKeyDir := t.TempDir()
	oldDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", emptyKeyDir)
	defer func() { viper.GetViper().Set("ONLINE_KEY_DIR", oldDir) }()
	_ = keyDir

	ctx := context.Background()
	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "failed to load delegation private key")
}

// To verify: In removeArtifactsFromDelegatedRole skip UploadMetadataToS3 error; test will fail (no error or wrong message).
func TestRemoveArtifactsFromDelegatedRole_UploadFails_ReturnsError(t *testing.T) {
	repo, _, _, tmpDir, redisClient, cleanup := makeRemoveArtifactsFromDelegatedRoleEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failUploadClient{}}
	}
	defer func() { tuf_storage.StorageFactoryForUpload = savedFactoryU }()

	ctx := context.Background()
	removed, err := removeArtifactsFromDelegatedRole(ctx, repo, "updates", []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "failed to upload updates metadata to S3")
}
