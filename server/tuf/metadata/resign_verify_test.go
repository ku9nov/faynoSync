package metadata

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"

	tuf_storage "faynoSync/server/tuf/storage"
)

type resignKey struct {
	key    *tuf_metadata.Key
	id     string
	signer signature.Signer
}

func newResignKey(t *testing.T) resignKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key, err := tuf_metadata.KeyFromPublicKey(priv.Public())
	require.NoError(t, err)
	id, err := key.ID()
	require.NoError(t, err)
	signer, err := signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)
	return resignKey{key: key, id: id, signer: signer}
}

// rotatedRoots returns root v1 and root v2 where v2 replaces the snapshot key
// and is signed by v2Signer (the v1 root key for a legitimate rotation).
func rotatedRoots(t *testing.T, rootKey, oldSnapshot, newSnapshot, timestampKey resignKey, v2Signer signature.Signer) (v1Bytes []byte, v2 *tuf_metadata.Metadata[tuf_metadata.RootType]) {
	t.Helper()
	expires := time.Now().Add(365 * 24 * time.Hour)
	v1 := tuf_metadata.Root(expires)
	require.NoError(t, v1.Signed.AddKey(rootKey.key, "root"))
	require.NoError(t, v1.Signed.AddKey(oldSnapshot.key, "snapshot"))
	require.NoError(t, v1.Signed.AddKey(timestampKey.key, "timestamp"))
	_, err := v1.Sign(rootKey.signer)
	require.NoError(t, err)
	v1Bytes, err = v1.ToBytes(false)
	require.NoError(t, err)

	v2, err = tuf_metadata.Root(expires).FromBytes(v1Bytes)
	require.NoError(t, err)
	require.NoError(t, v2.Signed.RevokeKey(oldSnapshot.id, "snapshot"))
	require.NoError(t, v2.Signed.AddKey(newSnapshot.key, "snapshot"))
	v2.Signed.Version = 2
	v2.ClearSignatures()
	_, err = v2.Sign(v2Signer)
	require.NoError(t, err)
	return v1Bytes, v2
}

// anchorRoots records the given root versions as server-verified, the way bootstrap and root updates do.
func anchorRoots(t *testing.T, files map[int64][]byte) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	for version, body := range files {
		require.NoError(t, anchorRootVersion(context.Background(), redisClient, "admin", "app", version, body))
	}
	return redisClient
}

// recordRotation stores the role digest the way recordRotatedRoleDigests does at root rotation.
func recordRotation(t *testing.T, redisClient *redis.Client, roleName string, md any) {
	t.Helper()
	digest, err := metadataContentDigest(md)
	require.NoError(t, err)
	require.NoError(t, redisClient.HSet(context.Background(), rotatedRoleDigestsKey("admin", "app"), roleName, digest).Err())
}

func signedSnapshot(t *testing.T, signer signature.Signer) *tuf_metadata.Metadata[tuf_metadata.SnapshotType] {
	t.Helper()
	snapshot := tuf_metadata.Snapshot(time.Now().Add(-time.Hour))
	_, err := snapshot.Sign(signer)
	require.NoError(t, err)
	return snapshot
}

// Expired but correctly signed metadata must be re-signable: that is what bumping is for.
// To verify: In VerifyForResign also check expiry; test will fail.
func TestVerifyForResign_ExpiredButSignedUnderCurrentRoot_Accepted(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	_, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)

	err := VerifyForResign(context.Background(), anchorRoots(t, nil), "admin", "app", root, "snapshot", signedSnapshot(t, newSnap.signer), t.TempDir())

	require.NoError(t, err)
}

// To verify: In VerifyForResign drop the previous-root fallback; test will fail (rotation blocks the bump).
func TestVerifyForResign_SignedWithRotatedKey_AcceptedUnderPreviousRoot(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes})
	redisClient := anchorRoots(t, map[int64][]byte{1: v1Bytes})
	snapshot := signedSnapshot(t, oldSnap.signer)
	recordRotation(t, redisClient, "snapshot", snapshot)

	err := VerifyForResign(context.Background(), redisClient, "admin", "app", root, "snapshot", snapshot, t.TempDir())

	require.NoError(t, err)
}

// To verify: In VerifyForResign return nil when signature verification fails; test will fail.
func TestVerifyForResign_ForgedSignature_Refused(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes})

	err := VerifyForResign(context.Background(), anchorRoots(t, map[int64][]byte{1: v1Bytes}), "admin", "app", root, "snapshot", signedSnapshot(t, newResignKey(t).signer), t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to re-sign snapshot")
}

// Snapshot rotated in v2, timestamp rotated in v3, snapshot never re-signed in
// between: it is still signed with the v1 key and must stay re-signable.
// To verify: In VerifyForResign only look one root back; test will fail.
func TestVerifyForResign_TwoRotationsBeforeResign_AcceptedUnderOldestRoot(t *testing.T) {
	rootKey, oldSnap, newSnap, oldTs, newTs := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, v2 := rotatedRoots(t, rootKey, oldSnap, newSnap, oldTs, rootKey.signer)
	v2Bytes, err := v2.ToBytes(false)
	require.NoError(t, err)

	v3, err := tuf_metadata.Root(time.Now()).FromBytes(v2Bytes)
	require.NoError(t, err)
	require.NoError(t, v3.Signed.RevokeKey(oldTs.id, "timestamp"))
	require.NoError(t, v3.Signed.AddKey(newTs.key, "timestamp"))
	v3.Signed.Version = 3
	v3.ClearSignatures()
	_, err = v3.Sign(rootKey.signer)
	require.NoError(t, err)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes, "2.root.json": v2Bytes})

	redisClient := anchorRoots(t, map[int64][]byte{1: v1Bytes, 2: v2Bytes})
	snapshot := signedSnapshot(t, oldSnap.signer)
	recordRotation(t, redisClient, "snapshot", snapshot)

	err = VerifyForResign(context.Background(), redisClient, "admin", "app", v3, "snapshot", snapshot, t.TempDir())

	require.NoError(t, err)
}

// A current root not signed by its predecessor is not a legitimate rotation.
// To verify: In VerifyForResign skip the prev.VerifyDelegate("root", newer) chain check; test will fail.
func TestVerifyForResign_CurrentRootNotSignedByPrevious_Refused(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, newResignKey(t).signer)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes})

	err := VerifyForResign(context.Background(), anchorRoots(t, map[int64][]byte{1: v1Bytes}), "admin", "app", root, "snapshot", signedSnapshot(t, oldSnap.signer), t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to re-sign snapshot")
	assert.Contains(t, err.Error(), "root v1 does not sign root v2")
}

// A forged older root that copies the real root keys (so it "signs" the current
// root) but swaps in an attacker snapshot key must not be usable for walk-back.
// To verify: In VerifyForResign load older roots without checking the anchored digest; test will fail (forged snapshot accepted).
func TestVerifyForResign_ForgedOlderRootInStorage_Refused(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey, attacker := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)

	forgedV1, err := tuf_metadata.Root(time.Now()).FromBytes(v1Bytes)
	require.NoError(t, err)
	require.NoError(t, forgedV1.Signed.RevokeKey(oldSnap.id, "snapshot"))
	require.NoError(t, forgedV1.Signed.AddKey(attacker.key, "snapshot"))
	forgedV1Bytes, err := forgedV1.ToBytes(false)
	require.NoError(t, err)
	serveMetadata(t, map[string][]byte{"1.root.json": forgedV1Bytes})

	err = VerifyForResign(context.Background(), anchorRoots(t, map[int64][]byte{1: v1Bytes}), "admin", "app", root, "snapshot", signedSnapshot(t, attacker.signer), t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the anchored digest")
}

// The attack from a leaked, rotated-out key: new content signed with it must not
// be re-signed with the current key, even though the old root verifies it.
// To verify: In VerifyForResign drop the verifyRotatedRoleDigest check; test will fail (forged snapshot accepted).
func TestVerifyForResign_ContentSignedWithRotatedKeyAfterRotation_Refused(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes})
	redisClient := anchorRoots(t, map[int64][]byte{1: v1Bytes})
	recordRotation(t, redisClient, "snapshot", signedSnapshot(t, oldSnap.signer))

	forged := tuf_metadata.Snapshot(time.Now().Add(time.Hour))
	forged.Signed.Version = 7
	_, err := forged.Sign(oldSnap.signer)
	require.NoError(t, err)

	err = VerifyForResign(context.Background(), redisClient, "admin", "app", root, "snapshot", forged, t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signed with keys from root v1 that were rotated out")
	assert.Contains(t, err.Error(), "differs from the one recorded at root rotation")
}

// To verify: In verifyRotatedRoleDigest treat a missing record as a match; test will fail.
func TestVerifyForResign_SignedWithRotatedKeyNothingRecorded_Refused(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes})

	err := VerifyForResign(context.Background(), anchorRoots(t, map[int64][]byte{1: v1Bytes}), "admin", "app", root, "snapshot", signedSnapshot(t, oldSnap.signer), t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no snapshot was recorded at root rotation")
}

// Once the role verifies under the current root the record must go, or the old
// file could be replayed and re-signed later.
// To verify: In VerifyForResign drop the HDel on the current-root path; test will fail.
func TestVerifyForResign_VerifiedUnderCurrentRoot_ClearsRecord(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	_, root := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)
	redisClient := anchorRoots(t, nil)
	recordRotation(t, redisClient, "snapshot", signedSnapshot(t, oldSnap.signer))

	require.NoError(t, VerifyForResign(context.Background(), redisClient, "admin", "app", root, "snapshot", signedSnapshot(t, newSnap.signer), t.TempDir()))

	exists, err := redisClient.HExists(context.Background(), rotatedRoleDigestsKey("admin", "app"), "snapshot").Result()
	require.NoError(t, err)
	assert.False(t, exists)
}

// Records the stored roles at rotation; afterwards the exact stored snapshot is
// re-signable under the new root and different content signed with the old key is not.
// To verify: In recordRotatedRoleDigests skip the HSet; test will fail (stored snapshot refused).
func TestRecordRotatedRoleDigests_StoredSnapshotStaysResignable(t *testing.T) {
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, v2 := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)
	v1, err := tuf_metadata.Root(time.Now()).FromBytes(v1Bytes)
	require.NoError(t, err)

	stored := tuf_metadata.Snapshot(time.Now().Add(time.Hour))
	stored.Signed.Version = 3
	_, err = stored.Sign(oldSnap.signer)
	require.NoError(t, err)
	storedBytes, err := stored.ToBytes(true)
	require.NoError(t, err)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes, "3.snapshot.json": storedBytes})
	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.root.json", "3.snapshot.json"}, nil
	}
	t.Cleanup(func() { tuf_storage.ListMetadataForLatest = savedList })
	redisClient := anchorRoots(t, map[int64][]byte{1: v1Bytes})

	require.NoError(t, recordRotatedRoleDigests(context.Background(), redisClient, "admin", "app", v1, t.TempDir()))

	reloaded, err := tuf_metadata.Snapshot().FromBytes(storedBytes)
	require.NoError(t, err)
	require.NoError(t, VerifyForResign(context.Background(), redisClient, "admin", "app", v2, "snapshot", reloaded, t.TempDir()))

	forged := tuf_metadata.Snapshot(time.Now().Add(time.Hour))
	forged.Signed.Version = 4
	_, err = forged.Sign(oldSnap.signer)
	require.NoError(t, err)
	err = VerifyForResign(context.Background(), redisClient, "admin", "app", v2, "snapshot", forged, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "differs from the one recorded at root rotation")
}

// End to end through bumpTargetsRole: forged targets in storage must not be re-signed or uploaded.
// To verify: remove the VerifyForResign call from bumpTargetsRole; test will fail (forged targets re-signed).
func TestBumpTargetsRole_ForgedTargets_RefusedBeforeUpload(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	forger := newResignKey(t)
	forgedTargetsJSON := makeValidTargetsJSON(t, repo, forger.signer, t.TempDir())

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: forgedTargetsJSON}}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		t.Fatal("forged targets must not be uploaded")
		return nil
	}
	t.Cleanup(func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	})

	err := bumpTargetsRole(context.Background(), repo, "admin", "app", redisClient, []signature.Signer{signer}, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to re-sign targets")
}

// Regression: the version floor in finalizeTargetsMetadataUpdate comes from the
// stored snapshot, so a forged snapshot must be refused, not re-signed.
// To verify: remove the VerifyForResign call from finalizeTargetsMetadataUpdate; test will fail (forged snapshot accepted).
func TestFinalizeTargetsMetadataUpdate_ForgedSnapshot_RefusedBeforeUpload(t *testing.T) {
	ctx := context.Background()
	repo, redisClient := setupFinalizeTargetsFixture(t, &uploadFailingMockClient{err: fmt.Errorf("upload must not be attempted")})
	repo.Targets("targets").Signed.Version = 2

	rootPath := filepath.Join(t.TempDir(), "1.root.json")
	require.NoError(t, tuf_storage.DownloadMetadataFromS3(ctx, "admin", "app", "1.root.json", rootPath))
	rootBody, err := os.ReadFile(rootPath)
	require.NoError(t, err)
	forged, err := signedSnapshot(t, newResignKey(t).signer).ToBytes(false)
	require.NoError(t, err)
	serveMetadata(t, map[string][]byte{"1.root.json": rootBody, "1.snapshot.json": forged})

	err = finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", t.TempDir(), redisClient)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to re-sign snapshot")
}

// To verify: In finalizeRootMetadataUpdate drop the recordRotatedRoleDigests call; test will fail (nothing recorded).
func TestFinalizeRootMetadataUpdate_RecordsStoredRolesBeforeRotation(t *testing.T) {
	ctx := context.Background()
	rootKey, oldSnap, newSnap, tsKey := newResignKey(t), newResignKey(t), newResignKey(t), newResignKey(t)
	v1Bytes, v2 := rotatedRoots(t, rootKey, oldSnap, newSnap, tsKey, rootKey.signer)

	stored := tuf_metadata.Snapshot(time.Now().Add(time.Hour))
	_, err := stored.Sign(oldSnap.signer)
	require.NoError(t, err)
	storedBytes, err := stored.ToBytes(false)
	require.NoError(t, err)
	serveMetadata(t, map[string][]byte{"1.root.json": v1Bytes, "1.snapshot.json": storedBytes})
	savedList := tuf_storage.ListMetadataForLatest
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.root.json", "1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	t.Cleanup(func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	})
	redisClient := anchorRoots(t, map[int64][]byte{1: v1Bytes})
	repo := repository.New()
	repo.SetRoot(v2)

	require.NoError(t, finalizeRootMetadataUpdate(ctx, repo, "admin", "app", t.TempDir(), false, "", redisClient))

	recorded, err := redisClient.HGet(ctx, rotatedRoleDigestsKey("admin", "app"), "snapshot").Result()
	require.NoError(t, err)
	want, err := metadataContentDigest(stored)
	require.NoError(t, err)
	assert.Equal(t, want, recorded)
}

func TestFinalizeTargetsMetadataUpdate_RetiresRotationRecordsAfterUpload(t *testing.T) {
	ctx := context.Background()
	repo, redisClient := setupFinalizeTargetsFixture(t, nil)
	repo.Targets("targets").Signed.Version = 2
	key := rotatedRoleDigestsKey("admin", "app")
	require.NoError(t, redisClient.HSet(ctx, key, "snapshot", "old", "timestamp", "old", "targets", "old").Err())

	require.NoError(t, finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", t.TempDir(), redisClient))

	left, err := redisClient.HKeys(ctx, key).Result()
	require.NoError(t, err)
	assert.Empty(t, left)
}

// To verify: In RetireRotatedRoleDigest delete a different field; test will fail.
func TestRetireRotatedRoleDigest_RemovesOnlyThatRole(t *testing.T) {
	ctx := context.Background()
	redisClient := anchorRoots(t, nil)
	key := rotatedRoleDigestsKey("admin", "app")
	require.NoError(t, redisClient.HSet(ctx, key, "snapshot", "a", "timestamp", "b").Err())

	RetireRotatedRoleDigest(ctx, redisClient, "admin", "app", "snapshot")

	left, err := redisClient.HKeys(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, []string{"timestamp"}, left)
}
