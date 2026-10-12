package metadata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	tuf_storage "faynoSync/server/tuf/storage"
)

// Digests of every root version the server has verified, kept outside the
// bucket: write access to the bucket alone must not be able to swap the root
// that online keys are used under.
func trustedRootsKey(adminName, appName string) string {
	return "TRUSTED_ROOTS_" + adminName + "_" + appName
}

func rootDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func anchorRootVersion(ctx context.Context, redisClient *redis.Client, adminName, appName string, version int64, data []byte) error {
	if err := redisClient.HSet(ctx, trustedRootsKey(adminName, appName), strconv.FormatInt(version, 10), rootDigest(data)).Err(); err != nil {
		return fmt.Errorf("failed to anchor root v%d: %w", version, err)
	}
	return nil
}

// A (re)bootstrap starts a new root chain, so anchors from a previous one are dropped.
func resetRootAnchor(ctx context.Context, redisClient *redis.Client, adminName, appName string, version int64, data []byte) error {
	if err := redisClient.Del(ctx, trustedRootsKey(adminName, appName)).Err(); err != nil {
		return fmt.Errorf("failed to reset root anchor: %w", err)
	}
	return anchorRootVersion(ctx, redisClient, adminName, appName, version, data)
}

func anchoredRootDigests(ctx context.Context, redisClient *redis.Client, adminName, appName string) (map[int64]string, int64, error) {
	raw, err := redisClient.HGetAll(ctx, trustedRootsKey(adminName, appName)).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read root anchor: %w", err)
	}
	digests := make(map[int64]string, len(raw))
	var latest int64
	for field, digest := range raw {
		version, err := strconv.ParseInt(field, 10, 64)
		if err != nil || version < 1 {
			return nil, 0, fmt.Errorf("invalid root anchor entry %q", field)
		}
		digests[version] = digest
		if version > latest {
			latest = version
		}
	}
	return digests, latest, nil
}

// LoadAnchoredRoot returns the newest root that chains to the anchored one: the
// anchored version must match its recorded digest, and every newer version in
// storage must be signed by its predecessor (TUF client root update rules).
// Without an anchor (existing deployments, lost Redis data) the chain is
// verified from 1.root.json and anchored, which is trust on first use.
func LoadAnchoredRoot(ctx context.Context, redisClient *redis.Client, adminName, appName, tmpDir string) (*metadata.Metadata[metadata.RootType], string, error) {
	if redisClient == nil {
		return nil, "", fmt.Errorf("redis client is required to load the trusted root")
	}
	latestVersion, _, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		return nil, "", fmt.Errorf("failed to find latest root version: %w", err)
	}
	if latestVersion < 1 {
		return nil, "", fmt.Errorf("no root metadata found in storage")
	}

	digests, anchoredVersion, err := anchoredRootDigests(ctx, redisClient, adminName, appName)
	if err != nil {
		return nil, "", err
	}
	if anchoredVersion > int64(latestVersion) {
		return nil, "", fmt.Errorf("refusing to use root: v%d is anchored but storage only has v%d", anchoredVersion, latestVersion)
	}

	var trusted *metadata.Metadata[metadata.RootType]
	var trustedPath string
	if anchoredVersion == 0 {
		logrus.Warnf("No trusted root anchor for %s/%s (key %s); verifying the root chain 1..%d from storage and anchoring it", adminName, appName, trustedRootsKey(adminName, appName), latestVersion)
		root, path, data, err := downloadRootVersion(ctx, adminName, appName, 1, tmpDir)
		if err != nil {
			return nil, "", err
		}
		if err := root.VerifyDelegate("root", root); err != nil {
			return nil, "", fmt.Errorf("refusing to use root: v1 is not signed by its own root keys: %w", err)
		}
		if err := anchorRootVersion(ctx, redisClient, adminName, appName, 1, data); err != nil {
			return nil, "", err
		}
		trusted, trustedPath, anchoredVersion = root, path, 1
	} else {
		trusted, trustedPath, err = loadAnchoredRootVersion(ctx, adminName, appName, anchoredVersion, digests[anchoredVersion], tmpDir)
		if err != nil {
			return nil, "", err
		}
	}

	for version := anchoredVersion + 1; version <= int64(latestVersion); version++ {
		next, path, data, err := downloadRootVersion(ctx, adminName, appName, version, tmpDir)
		if err != nil {
			return nil, "", err
		}
		if err := verifyNewRootMetadata(trusted, next); err != nil {
			return nil, "", fmt.Errorf("refusing to use root v%d: not a trusted successor of v%d: %w", version, trusted.Signed.Version, err)
		}
		if err := anchorRootVersion(ctx, redisClient, adminName, appName, version, data); err != nil {
			return nil, "", err
		}
		logrus.Infof("Anchored root v%d for %s/%s", version, adminName, appName)
		trusted, trustedPath = next, path
	}

	return trusted, trustedPath, nil
}

func loadAnchoredRootVersion(ctx context.Context, adminName, appName string, version int64, digest, tmpDir string) (*metadata.Metadata[metadata.RootType], string, error) {
	if digest == "" {
		return nil, "", fmt.Errorf("root v%d is not anchored", version)
	}
	root, path, data, err := downloadRootVersion(ctx, adminName, appName, version, tmpDir)
	if err != nil {
		return nil, "", err
	}
	if rootDigest(data) != digest {
		return nil, "", fmt.Errorf("refusing to use root v%d: stored file does not match the anchored digest", version)
	}
	return root, path, nil
}

func downloadRootVersion(ctx context.Context, adminName, appName string, version int64, tmpDir string) (*metadata.Metadata[metadata.RootType], string, []byte, error) {
	filename := fmt.Sprintf("%d.root.json", version)
	path := filepath.Join(tmpDir, "anchored_"+filename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, path); err != nil {
		return nil, "", nil, fmt.Errorf("failed to download %s: %w", filename, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to read %s: %w", filename, err)
	}
	root, err := metadata.Root(time.Now()).FromBytes(data)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to load %s: %w", filename, err)
	}
	if root.Signed.Version != version {
		return nil, "", nil, fmt.Errorf("%s declares version %d", filename, root.Signed.Version)
	}
	return root, path, data, nil
}
