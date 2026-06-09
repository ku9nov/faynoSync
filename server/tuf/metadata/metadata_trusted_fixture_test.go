package metadata

import (
	"context"
	"crypto"
	"crypto/ed25519"
	tuf_storage "faynoSync/server/tuf/storage"
	"fmt"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// The trusted-store loaders now verify signatures against the root chain before returning
// (invariant 6). These helpers build a properly signed root + targets (+ delegated roles) so
// tests exercise the real verification path instead of feeding unsigned blobs.

type fixtureDelegation struct {
	role      string
	version   int64
	key       *tuf_metadata.Key // declaration key; nil => generate ed25519
	signer    signature.Signer  // signer for the delegated role file (auto-set when key is generated)
	buildFile bool              // emit a signed <ver>.<role>.json into the store
	keyID     string            // out: computed key ID of the declaration key
}

type trustedStoreFixture struct {
	bodies    map[string][]byte
	filenames []string
}

func buildTrustedStoreFixture(t *testing.T, targetsVersion int64, delegations []*fixtureDelegation) trustedStoreFixture {
	t.Helper()
	expires := time.Now().Add(365 * 24 * time.Hour)
	repo := repository.New()
	repo.SetRoot(tuf_metadata.Root(expires))
	repo.SetTargets("targets", tuf_metadata.Targets(expires))

	keys := map[string]ed25519.PrivateKey{}
	for _, name := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		keys[name] = priv
		key, err := tuf_metadata.KeyFromPublicKey(priv.Public())
		require.NoError(t, err)
		require.NoError(t, repo.Root().Signed.AddKey(key, name))
	}

	if targetsVersion > 0 {
		repo.Targets("targets").Signed.Version = targetsVersion
	}

	if len(delegations) > 0 {
		delegs := &tuf_metadata.Delegations{
			Keys:  map[string]*tuf_metadata.Key{},
			Roles: []tuf_metadata.DelegatedRole{},
		}
		for _, d := range delegations {
			if d.key == nil {
				_, dpriv, err := ed25519.GenerateKey(nil)
				require.NoError(t, err)
				d.key, err = tuf_metadata.KeyFromPublicKey(dpriv.Public())
				require.NoError(t, err)
				d.signer, err = signature.LoadSigner(dpriv, crypto.Hash(0))
				require.NoError(t, err)
			}
			keyID, err := d.key.ID()
			require.NoError(t, err)
			d.keyID = keyID
			delegs.Keys[keyID] = d.key
			delegs.Roles = append(delegs.Roles, tuf_metadata.DelegatedRole{
				Name:      d.role,
				KeyIDs:    []string{keyID},
				Threshold: 1,
				Paths:     []string{"*"},
			})
		}
		repo.Targets("targets").Signed.Delegations = delegs
	}

	rootSigner, err := signature.LoadSigner(keys["root"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = repo.Root().Sign(rootSigner)
	require.NoError(t, err)

	targetsSigner, err := signature.LoadSigner(keys["targets"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = repo.Targets("targets").Sign(targetsSigner)
	require.NoError(t, err)

	bodies := map[string][]byte{}
	var filenames []string

	rootJSON, err := repo.Root().ToBytes(true)
	require.NoError(t, err)
	bodies["1.root.json"] = rootJSON
	filenames = append(filenames, "1.root.json")

	tv := targetsVersion
	if tv <= 0 {
		tv = 1
	}
	targetsFile := fmt.Sprintf("%d.targets.json", tv)
	targetsJSON, err := repo.Targets("targets").ToBytes(true)
	require.NoError(t, err)
	bodies[targetsFile] = targetsJSON
	filenames = append(filenames, targetsFile)

	for _, d := range delegations {
		if !d.buildFile {
			continue
		}
		dv := d.version
		if dv <= 0 {
			dv = 1
		}
		delMeta := tuf_metadata.Targets(expires)
		delMeta.Signed.Version = dv
		_, err = delMeta.Sign(d.signer)
		require.NoError(t, err)
		delFile := fmt.Sprintf("%d.%s.json", dv, d.role)
		delJSON, err := delMeta.ToBytes(true)
		require.NoError(t, err)
		bodies[delFile] = delJSON
		filenames = append(filenames, delFile)
	}

	// Snapshot binds the targets and delegated-role versions; the rollback floor for
	// delegated signing is read from here (root -> snapshot), so the fixture must carry it.
	snap := tuf_metadata.Snapshot(expires)
	snap.Signed.Version = 1
	snap.Signed.Meta["targets.json"] = &tuf_metadata.MetaFiles{Version: tv}
	for _, d := range delegations {
		dv := d.version
		if dv <= 0 {
			dv = 1
		}
		snap.Signed.Meta[fmt.Sprintf("%s.json", d.role)] = &tuf_metadata.MetaFiles{Version: dv}
	}
	snapshotSigner, err := signature.LoadSigner(keys["snapshot"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = snap.Sign(snapshotSigner)
	require.NoError(t, err)
	snapJSON, err := snap.ToBytes(true)
	require.NoError(t, err)
	bodies["1.snapshot.json"] = snapJSON
	filenames = append(filenames, "1.snapshot.json")

	return trustedStoreFixture{bodies: bodies, filenames: filenames}
}

// To verify: drop the VerifyDelegate call in loadVerifiedTrustedTargetsRole; this test fails
// (a targets blob not signed by the root-authorized targets key would be accepted).
func TestLoadTrustedTargetsFromS3_TamperedSignature_Rejected(t *testing.T) {
	ctx := context.Background()
	fixture := buildTrustedStoreFixture(t, 1, nil)

	// Forge a structurally valid targets blob signed by a key the trusted root does not authorize.
	_, rogue, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	rogueSigner, err := signature.LoadSigner(rogue, crypto.Hash(0))
	require.NoError(t, err)
	forged := tuf_metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
	_, err = forged.Sign(rogueSigner)
	require.NoError(t, err)
	forgedJSON, err := forged.ToBytes(true)
	require.NoError(t, err)

	tampered := trustedStoreFixture{
		bodies: map[string][]byte{
			"1.root.json":    fixture.bodies["1.root.json"],
			"1.targets.json": forgedJSON,
		},
		filenames: []string{"1.root.json", "1.targets.json"},
	}
	defer tampered.install(t, nil)()

	result, err := loadTrustedTargetsFromS3(ctx, "admin", "myapp")

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "signature verification failed")
}

// install wires the fixture into the storage download hooks and returns a restore func.
// When listFilenames is nil the full fixture file list is advertised.
func (f trustedStoreFixture) install(t *testing.T, listFilenames []string) func() {
	t.Helper()
	if listFilenames == nil {
		listFilenames = f.filenames
	}

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return listFilenames, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &multiBodyDownloadMock{bodies: f.bodies}}
	}

	return func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}
}
