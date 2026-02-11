package artifacts

import (
	"testing"

	"faynoSync/server/model"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func makeMongoArtifact(link string, hashes map[string]string, length int64) model.Artifact {
	return model.Artifact{
		Link:     link,
		Platform: primitive.NilObjectID,
		Arch:     primitive.NilObjectID,
		Hashes:   hashes,
		Length:   length,
	}
}

// To verify: Modify ExtractTUFPathFromLink in server/tuf/utils/utils.go to return an error
func TestConvertMongoArtifactToTUF_Success_PrivateLink(t *testing.T) {
	env := viper.New()
	env.Set("API_URL", "http://api.example.com")

	link := "http://api.example.com/download?key=app%2Fv1%2Ffile.bin"
	hashes := map[string]string{"sha256": "abc123def456"}
	length := int64(1024)

	mongoArtifact := makeMongoArtifact(link, hashes, length)

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, true, env)
	require.NoError(t, err, "ConvertMongoArtifactToTUF must not return error for valid private link")
	require.NotNil(t, got)

	assert.Equal(t, "app/v1/file.bin", got.Path, "TUF path must be URL-decoded S3 key")
	assert.Equal(t, length, got.Info.Length, "Length must be preserved")
	assert.Equal(t, hashes, got.Info.Hashes, "Hashes must be preserved")
	assert.Nil(t, got.Info.Custom, "Custom must be nil")
}

// To verify: Modify ExtractTUFPathFromLink (or ExtractS3Key) to return an error for valid
func TestConvertMongoArtifactToTUF_Success_PublicLink(t *testing.T) {
	env := viper.New()
	env.Set("S3_ENDPOINT", "https://s3.example.com")
	env.Set("S3_BUCKET_NAME", "my-bucket")

	link := "https://s3.example.com/my-bucket/app/v1/artifact.bin"
	hashes := map[string]string{"sha256": "xyz789"}
	length := int64(2048)

	mongoArtifact := makeMongoArtifact(link, hashes, length)

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, false, env)
	require.NoError(t, err, "ConvertMongoArtifactToTUF must not return error for valid public link")
	require.NotNil(t, got)

	assert.Equal(t, "app/v1/artifact.bin", got.Path, "TUF path must match extracted S3 key")
	assert.Equal(t, length, got.Info.Length)
	assert.Equal(t, hashes, got.Info.Hashes)
}

// To verify: In ConvertMongoArtifactToTUF, remove or bypass the check "if len(mongoArtifact.Hashes) == 0" so that artifacts with no hashes are accepted; this test will then fail (no error returned).
func TestConvertMongoArtifactToTUF_NoHashes_ReturnsError(t *testing.T) {
	env := viper.New()
	env.Set("API_URL", "http://api.example.com")

	mongoArtifact := makeMongoArtifact("http://api.example.com/download?key=app/file.bin", nil, 100)
	mongoArtifact.Hashes = nil

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, true, env)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "no hashes", "error message must mention hashes")
}

// To verify: In ConvertMongoArtifactToTUF, remove or bypass the check "if len(mongoArtifact.Hashes) == 0" so that empty map is accepted; this test will then fail.
func TestConvertMongoArtifactToTUF_EmptyHashes_ReturnsError(t *testing.T) {
	env := viper.New()
	env.Set("API_URL", "http://api.example.com")

	mongoArtifact := makeMongoArtifact("http://api.example.com/download?key=app/file.bin", map[string]string{}, 100)

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, true, env)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "no hashes", "error message must mention hashes")
}

// To verify: In ConvertMongoArtifactToTUF, remove or bypass the check "if mongoArtifact.Length == 0" so that zero length is accepted; this test will then fail (no error returned).
func TestConvertMongoArtifactToTUF_ZeroLength_ReturnsError(t *testing.T) {
	env := viper.New()
	env.Set("API_URL", "http://api.example.com")

	mongoArtifact := makeMongoArtifact("http://api.example.com/download?key=app/file.bin", map[string]string{"sha256": "abc"}, 0)

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, true, env)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "no length", "error message must mention length")
}

// To verify: In ConvertMongoArtifactToTUF, change the call to ExtractTUFPathFromLink so it never returns an error for empty link (e.g. return "dummy", nil); this test will then fail (no error).
func TestConvertMongoArtifactToTUF_EmptyLink_ReturnsError(t *testing.T) {
	env := viper.New()
	mongoArtifact := makeMongoArtifact("", map[string]string{"sha256": "abc"}, 100)

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, true, env)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "extract TUF path", "error must be about TUF path extraction")
}

// To verify: Change ConvertMongoArtifactToTUF so that ArtifactInfo.Custom is set to a non-nil value (e.g. empty map); this test will then fail because Custom must remain nil.
func TestConvertMongoArtifactToTUF_CustomIsNil(t *testing.T) {
	env := viper.New()
	env.Set("API_URL", "http://api.example.com")

	mongoArtifact := makeMongoArtifact("http://api.example.com/download?key=app/file.bin", map[string]string{"sha256": "a"}, 1)

	got, err := ConvertMongoArtifactToTUF(mongoArtifact, true, env)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.Info.Custom, "Custom must be nil in TUF artifact info")
}
