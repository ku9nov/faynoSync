package metadata

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// VerifyForResign refuses to re-sign stored metadata whose signature does not
// verify: write access to the bucket must not be enough to get forged content
// signed with an online key. Expiry is deliberately not checked, since bumping
// expiring or expired metadata is the point of re-signing.
//
// After online key rotations the stored file can still be signed with keys from
// an earlier root (several rotations may land before the next re-sign), so the
// root history is walked back, each step checked against its anchored digest and
// to sign its successor, and the file is accepted under the first root whose
// keys it verifies against. root must come from LoadAnchoredRoot.
func VerifyForResign(ctx context.Context, redisClient *redis.Client, adminName, appName string, root *metadata.Metadata[metadata.RootType], roleName string, md any, tmpDir string) error {
	if root == nil {
		return fmt.Errorf("refusing to re-sign %s: root metadata not loaded", roleName)
	}
	currentErr := root.VerifyDelegate(roleName, md)
	if currentErr == nil {
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
			logrus.Infof("Stored %s metadata is signed with keys from root v%d (current root v%d); re-signing it with the current keys", roleName, prev.Signed.Version, root.Signed.Version)
			return nil
		}
		newer = prev
	}

	return fmt.Errorf("refusing to re-sign %s: signature does not verify against root v%d or any earlier root: %w", roleName, root.Signed.Version, currentErr)
}
