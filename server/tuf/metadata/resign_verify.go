package metadata

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/go-redis/redis/v8"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	tuf_storage "faynoSync/server/tuf/storage"
)

var resignedRoles = []string{"targets", "snapshot", "timestamp"}

// VerifyForResign refuses to re-sign stored metadata whose signature does not
// verify: write access to the bucket must not be enough to get forged content
// signed with an online key. Expiry is deliberately not checked, since bumping
// expiring or expired metadata is the point of re-signing.
//
// After online key rotations the stored file can still be signed with keys from
// an earlier root (several rotations may land before the next re-sign), so the
// root history is walked back, each step checked against its anchored digest and
// to sign its successor, and the file is accepted under the first root whose
// keys it verifies against. A rotated-out key may have leaked, so a file accepted
// that way must also be the exact one the server held when the root was rotated
// (recordRotatedRoleDigests). root must come from LoadAnchoredRoot.
func VerifyForResign(ctx context.Context, redisClient *redis.Client, adminName, appName string, root *metadata.Metadata[metadata.RootType], roleName string, md any, tmpDir string) error {
	if root == nil {
		return fmt.Errorf("refusing to re-sign %s: root metadata not loaded", roleName)
	}
	currentErr := root.VerifyDelegate(roleName, md)
	if currentErr == nil {
		if err := redisClient.HDel(ctx, rotatedRoleDigestsKey(adminName, appName), roleName).Err(); err != nil {
			return fmt.Errorf("refusing to re-sign %s: failed to clear rotated role digest: %w", roleName, err)
		}
		return nil
	}

	digests, _, err := anchoredRootDigests(ctx, redisClient, adminName, appName)
	if err != nil {
		return fmt.Errorf("refusing to re-sign %s: signature does not verify against root v%d: %w (root history unavailable: %v)", roleName, root.Signed.Version, currentErr, err)
	}

	newer := root
	for version := root.Signed.Version - 1; version >= 1; version-- {
		prev, _, err := loadAnchoredRootVersion(ctx, adminName, appName, version, digests[version], tmpDir)
		if err != nil {
			return fmt.Errorf("refusing to re-sign %s: signature does not verify against root v%d: %w (root history unavailable: %v)", roleName, root.Signed.Version, currentErr, err)
		}
		if err := prev.VerifyDelegate("root", newer); err != nil {
			return fmt.Errorf("refusing to re-sign %s: signature does not verify against root v%d: %w (root v%d does not sign root v%d: %v)", roleName, root.Signed.Version, currentErr, prev.Signed.Version, newer.Signed.Version, err)
		}
		if prev.VerifyDelegate(roleName, md) == nil {
			if err := verifyRotatedRoleDigest(ctx, redisClient, adminName, appName, roleName, md); err != nil {
				return fmt.Errorf("refusing to re-sign %s: signed with keys from root v%d that were rotated out: %w", roleName, prev.Signed.Version, err)
			}
			logrus.Infof("Stored %s metadata is signed with keys from root v%d (current root v%d); re-signing it with the current keys", roleName, prev.Signed.Version, root.Signed.Version)
			return nil
		}
		newer = prev
	}

	return fmt.Errorf("refusing to re-sign %s: signature does not verify against root v%d or any earlier root: %w", roleName, root.Signed.Version, currentErr)
}

// The upload has already happened, so the error is logged: returning it would not
// remove the record and would only leave the publish half-done. VerifyForResign
// clears the record again on the next current-root verification and fails closed.
func RetireRotatedRoleDigest(ctx context.Context, redisClient *redis.Client, adminName, appName, roleName string) {
	if err := redisClient.HDel(ctx, rotatedRoleDigestsKey(adminName, appName), roleName).Err(); err != nil {
		logrus.Errorf("Failed to retire rotated %s digest for %s/%s: %v", roleName, adminName, appName, err)
	}
}

func rotatedRoleDigestsKey(adminName, appName string) string {
	return "ROTATED_ROLE_DIGESTS_" + adminName + "_" + appName
}

// Digest of the parsed content, so it does not depend on how the stored file is formatted.
func metadataContentDigest(md any) (string, error) {
	data, err := cjson.EncodeCanonical(md)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize metadata: %w", err)
	}
	return rootDigest(data), nil
}

func verifyRotatedRoleDigest(ctx context.Context, redisClient *redis.Client, adminName, appName, roleName string, md any) error {
	recorded, err := redisClient.HGet(ctx, rotatedRoleDigestsKey(adminName, appName), roleName).Result()
	if err == redis.Nil {
		return fmt.Errorf("no %s was recorded at root rotation", roleName)
	}
	if err != nil {
		return fmt.Errorf("failed to read rotated role digest: %w", err)
	}
	digest, err := metadataContentDigest(md)
	if err != nil {
		return err
	}
	if digest != recorded {
		return fmt.Errorf("stored %s differs from the one recorded at root rotation", roleName)
	}
	return nil
}

// Called before a new root is persisted, while trustedRoot is still the current
// one: records the online roles the server holds so they stay re-signable after
// the rotation. A role that does not verify is not recorded and stays refused.
func recordRotatedRoleDigests(ctx context.Context, redisClient *redis.Client, adminName, appName string, trustedRoot *metadata.Metadata[metadata.RootType], tmpDir string) error {
	for _, roleName := range resignedRoles {
		md, err := loadStoredOnlineRole(ctx, adminName, appName, roleName, tmpDir)
		if err != nil {
			logrus.Warnf("Root rotation for %s/%s: %s not recorded, it will not be re-signable until it verifies under the new root: %v", adminName, appName, roleName, err)
			continue
		}
		if err := VerifyForResign(ctx, redisClient, adminName, appName, trustedRoot, roleName, md, tmpDir); err != nil {
			logrus.Warnf("Root rotation for %s/%s: %s not recorded, it will not be re-signable until it verifies under the new root: %v", adminName, appName, roleName, err)
			continue
		}
		digest, err := metadataContentDigest(md)
		if err != nil {
			return err
		}
		if err := redisClient.HSet(ctx, rotatedRoleDigestsKey(adminName, appName), roleName, digest).Err(); err != nil {
			return fmt.Errorf("failed to record rotated %s digest: %w", roleName, err)
		}
	}
	return nil
}

func loadStoredOnlineRole(ctx context.Context, adminName, appName, roleName, tmpDir string) (any, error) {
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, roleName)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(tmpDir, "rotation-"+filename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, path); err != nil {
		return nil, err
	}
	switch roleName {
	case "targets":
		return metadata.Targets().FromFile(path)
	case "snapshot":
		return metadata.Snapshot().FromFile(path)
	case "timestamp":
		return metadata.Timestamp().FromFile(path)
	}
	return nil, fmt.Errorf("unsupported role %s", roleName)
}
