package metadata

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"

	tuf_storage "faynoSync/server/tuf/storage"
)

type rootChain struct {
	rootKey resignKey
	bodies  map[int64][]byte
}

// newRootChain builds root v1..n, each signed by the same root key, with a fresh snapshot key per version.
func newRootChain(t *testing.T, n int64) rootChain {
	t.Helper()
	chain := rootChain{rootKey: newResignKey(t), bodies: map[int64][]byte{}}
	for version := int64(1); version <= n; version++ {
		root := tuf_metadata.Root(time.Now().Add(365 * 24 * time.Hour))
		root.Signed.Version = version
		require.NoError(t, root.Signed.AddKey(chain.rootKey.key, "root"))
		require.NoError(t, root.Signed.AddKey(newResignKey(t).key, "snapshot"))
		_, err := root.Sign(chain.rootKey.signer)
		require.NoError(t, err)
		chain.bodies[version], err = root.ToBytes(false)
		require.NoError(t, err)
	}
	return chain
}

func serveRoots(t *testing.T, bodies map[int64][]byte) {
	t.Helper()
	files := map[string][]byte{}
	var names []string
	for version, body := range bodies {
		name := rootFilenameForTest(version)
		files[name] = body
		names = append(names, name)
	}
	serveMetadata(t, files)
	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return names, nil
	}
	t.Cleanup(func() { tuf_storage.ListMetadataForLatest = savedList })
}

func rootFilenameForTest(version int64) string {
	return map[int64]string{1: "1.root.json", 2: "2.root.json", 3: "3.root.json"}[version]
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	return redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
}

// The attack from the review: bucket write access alone adds a root N+1 that
// declares an attacker key, so forged metadata would verify and get re-signed.
// To verify: In LoadAnchoredRoot skip verifyNewRootMetadata for newer versions; test will fail (forged root accepted).
func TestLoadAnchoredRoot_ForgedNewerRoot_Refused(t *testing.T) {
	chain := newRootChain(t, 1)
	forged := newRootChain(t, 2).bodies[2]
	serveRoots(t, map[int64][]byte{1: chain.bodies[1], 2: forged})
	redisClient := newTestRedis(t)
	require.NoError(t, anchorRootVersion(context.Background(), redisClient, "admin", "app", 1, chain.bodies[1]))

	_, _, err := LoadAnchoredRoot(context.Background(), redisClient, "admin", "app", t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to use root v2: not a trusted successor of v1")
}

// To verify: In LoadAnchoredRoot stop anchoring verified successors; test will fail (anchor stays at v1).
func TestLoadAnchoredRoot_LegitimateRotation_AdvancesAnchor(t *testing.T) {
	chain := newRootChain(t, 3)
	serveRoots(t, chain.bodies)
	redisClient := newTestRedis(t)
	require.NoError(t, anchorRootVersion(context.Background(), redisClient, "admin", "app", 1, chain.bodies[1]))

	root, _, err := LoadAnchoredRoot(context.Background(), redisClient, "admin", "app", t.TempDir())

	require.NoError(t, err)
	assert.Equal(t, int64(3), root.Signed.Version)
	digests, anchored, err := anchoredRootDigests(context.Background(), redisClient, "admin", "app")
	require.NoError(t, err)
	assert.Equal(t, int64(3), anchored)
	assert.Equal(t, rootDigest(chain.bodies[2]), digests[2])
}

// To verify: In loadAnchoredRootVersion skip the digest comparison; test will fail (replaced root accepted).
func TestLoadAnchoredRoot_AnchoredRootReplacedInStorage_Refused(t *testing.T) {
	chain := newRootChain(t, 1)
	serveRoots(t, map[int64][]byte{1: newRootChain(t, 1).bodies[1]})
	redisClient := newTestRedis(t)
	require.NoError(t, anchorRootVersion(context.Background(), redisClient, "admin", "app", 1, chain.bodies[1]))

	_, _, err := LoadAnchoredRoot(context.Background(), redisClient, "admin", "app", t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the anchored digest")
}

// Deleting the newest root from the bucket must not roll trust back to an older one.
// To verify: In LoadAnchoredRoot drop the anchoredVersion > latestVersion check; test will fail (rollback accepted).
func TestLoadAnchoredRoot_StorageBehindAnchor_Refused(t *testing.T) {
	chain := newRootChain(t, 2)
	serveRoots(t, map[int64][]byte{1: chain.bodies[1]})
	redisClient := newTestRedis(t)
	require.NoError(t, anchorRootVersion(context.Background(), redisClient, "admin", "app", 1, chain.bodies[1]))
	require.NoError(t, anchorRootVersion(context.Background(), redisClient, "admin", "app", 2, chain.bodies[2]))

	_, _, err := LoadAnchoredRoot(context.Background(), redisClient, "admin", "app", t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "v2 is anchored but storage only has v1")
}

// Existing deployments have no anchor yet: the stored chain is verified and anchored.
// To verify: In LoadAnchoredRoot skip anchoring in the no-anchor branch; test will fail (no anchor written).
func TestLoadAnchoredRoot_NoAnchor_VerifiesChainAndAnchors(t *testing.T) {
	chain := newRootChain(t, 2)
	serveRoots(t, chain.bodies)
	redisClient := newTestRedis(t)

	root, _, err := LoadAnchoredRoot(context.Background(), redisClient, "admin", "app", t.TempDir())

	require.NoError(t, err)
	assert.Equal(t, int64(2), root.Signed.Version)
	digests, anchored, err := anchoredRootDigests(context.Background(), redisClient, "admin", "app")
	require.NoError(t, err)
	assert.Equal(t, int64(2), anchored)
	assert.Equal(t, rootDigest(chain.bodies[1]), digests[1])
}

// To verify: In LoadAnchoredRoot skip the v1 self-signature check in the no-anchor branch; test will fail (unsigned v1 anchored).
func TestLoadAnchoredRoot_NoAnchor_UnsignedV1_Refused(t *testing.T) {
	unsigned, err := tuf_metadata.Root(time.Now().Add(time.Hour)).ToBytes(false)
	require.NoError(t, err)
	serveRoots(t, map[int64][]byte{1: unsigned})
	redisClient := newTestRedis(t)

	_, _, err = LoadAnchoredRoot(context.Background(), redisClient, "admin", "app", t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "v1 is not signed by its own root keys")
	_, anchored, err := anchoredRootDigests(context.Background(), redisClient, "admin", "app")
	require.NoError(t, err)
	assert.Zero(t, anchored)
}
