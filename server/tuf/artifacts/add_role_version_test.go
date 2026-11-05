package artifacts

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	tuf_storage "faynoSync/server/tuf/storage"
	tuf_utils "faynoSync/server/tuf/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// A failed storage listing is not "the role does not exist yet": treating it so re-creates
// the role at version 2 with only the new artifacts and drops every target signed before.
// To verify: In updateDelegatedRoleWithArtifacts set isNewDelegation for any FindLatestMetadataVersion error; test will fail (2.updates.json uploaded).
func TestUpdateDelegatedRoleWithArtifacts_ListFails_ReturnsErrorWithoutNewRole(t *testing.T) {
	repo, _, cleanup := makeRepoAndKeyForUpdateDelegatedRole(t, "updates")
	defer cleanup()

	savedList := tuf_storage.ListMetadataForLatest
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("transient list failure")
	}
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		t.Fatal("no delegated role may be uploaded when the existing one could not be listed")
		return nil
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	redisClient := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	artifacts := []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{Length: 1024, Hashes: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
	}

	_, err := updateDelegatedRoleWithArtifacts(context.Background(), repo, "updates", artifacts, testAdminName, testAppName, redisClient, t.TempDir())

	require.Error(t, err)
}

// Snapshot must never bind a delegated role at a version lower than or equal to the one it already binds.
// To verify: In updateSnapshotAndTimestamp write the role's meta without comparing it to the loaded snapshot; test will fail (snapshot uploaded).
func TestUpdateSnapshotAndTimestamp_DelegatedVersionNotIncreasing_Refused(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	storeDir := t.TempDir()
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))

	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	repo := repository.New()
	setRootTrustingSigner(t, repo, snapSigner)
	stored := tuf_metadata.Snapshot(tuf_utils.HelperExpireIn(7))
	stored.Signed.Meta["updates.json"] = &tuf_metadata.MetaFiles{Version: 5}
	repo.SetSnapshot(stored)
	_, err := repo.Snapshot().Sign(snapSigner)
	require.NoError(t, err)
	require.NoError(t, repo.Snapshot().ToFile(filepath.Join(metadataPrefix, "1.snapshot.json"), true))

	rolled := tuf_metadata.Targets(tuf_utils.HelperExpireIn(7))
	rolled.Signed.Version = 2
	repo.SetTargets("updates", rolled)

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
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
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		t.Fatal("a snapshot lowering updates.json from 5 to 2 must not be signed and uploaded")
		return nil
	}
	t.Cleanup(func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	})

	err = updateSnapshotAndTimestamp(context.Background(), repo, []string{"updates"}, testAdminName, testAppName, redisClient,
		[]signature.Signer{tsSigner}, []signature.Signer{snapSigner}, t.TempDir())

	require.Error(t, err)
}
