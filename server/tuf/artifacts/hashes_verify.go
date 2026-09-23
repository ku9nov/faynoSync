package artifacts

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/storage"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type objectHashSource interface {
	StatObject(ctx context.Context, bucketName, objectKey string) (storage.ObjectStat, error)
	OpenObject(ctx context.Context, bucketName, objectKey string) (io.ReadCloser, error)
}

var newObjectHashSource = func(env *viper.Viper) (objectHashSource, error) {
	client, err := storage.NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		return nil, err
	}
	source, ok := client.(objectHashSource)
	if !ok {
		return nil, fmt.Errorf("storage driver %q cannot read back stored objects", env.GetString("STORAGE_DRIVER"))
	}
	return source, nil
}

// verifyUnverifiedArtifacts checks artifacts whose hashes faynoSync did not compute itself
// against the bytes in storage. Any failure rejects the whole publish, so a version is
// never left partly signed.
func verifyUnverifiedArtifacts(ctx context.Context, env *viper.Viper, artifacts []model.Artifact) ([]model.Artifact, error) {
	var pending []model.Artifact
	for _, artifact := range artifacts {
		if !artifact.HashesVerified {
			pending = append(pending, artifact)
		}
	}
	if len(pending) == 0 {
		return nil, nil
	}

	source, err := newObjectHashSource(env)
	if err != nil {
		return nil, fmt.Errorf("cannot verify artifact hashes: %w", err)
	}

	var failures []string
	for _, artifact := range pending {
		private := strings.Contains(artifact.Link, "/download?key=")
		key, err := utils.ExtractS3Key(artifact.Link, private, env)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", artifact.Link, err))
			continue
		}
		bucket := env.GetString("S3_BUCKET_NAME")
		if private {
			bucket = env.GetString("S3_BUCKET_NAME_PRIVATE")
		}

		if err := verifyArtifactHashes(ctx, source, bucket, key, artifact); err != nil {
			logrus.Errorf("Artifact hash verification failed: key=%s: %v", key, err)
			failures = append(failures, fmt.Sprintf("%s: %v", key, err))
			continue
		}
		logrus.Debugf("Artifact hashes verified against storage: key=%s", key)
	}

	if len(failures) > 0 {
		return nil, fmt.Errorf("artifact hashes do not match stored bytes, nothing was signed: %s", strings.Join(failures, "; "))
	}
	return pending, nil
}

// verifyArtifactHashes uses the storage-computed sha256 when the provider has one, and
// streams the object otherwise. sha512 is only checked on the streaming path: providers
// never compute it, and a wrong sha512 still fails closed on TUF clients.
func verifyArtifactHashes(ctx context.Context, source objectHashSource, bucket, key string, artifact model.Artifact) error {
	declaredSHA256, ok := artifact.Hashes["sha256"]
	if !ok {
		return errors.New("no sha256")
	}
	for algorithm := range artifact.Hashes {
		if algorithm != "sha256" && algorithm != "sha512" {
			return fmt.Errorf("unsupported hash algorithm %q", algorithm)
		}
	}

	stat, err := source.StatObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if stat.Size != artifact.Length {
		return fmt.Errorf("length %d, stored %d", artifact.Length, stat.Size)
	}
	if stat.SHA256 != "" {
		if !strings.EqualFold(stat.SHA256, declaredSHA256) {
			return errors.New("sha256 mismatch")
		}
		return nil
	}

	started := time.Now()
	body, err := source.OpenObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer body.Close()

	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	streamed, err := io.Copy(io.MultiWriter(sha256Hash, sha512Hash), body)
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	logrus.Debugf("Streamed %d bytes of %s for hash verification in %s", streamed, key, time.Since(started))

	if streamed != artifact.Length {
		return fmt.Errorf("length %d, streamed %d", artifact.Length, streamed)
	}
	if !strings.EqualFold(hex.EncodeToString(sha256Hash.Sum(nil)), declaredSHA256) {
		return errors.New("sha256 mismatch")
	}
	if declaredSHA512, ok := artifact.Hashes["sha512"]; ok && !strings.EqualFold(hex.EncodeToString(sha512Hash.Sum(nil)), declaredSHA512) {
		return errors.New("sha512 mismatch")
	}
	return nil
}

func markArtifactsHashesVerified(ctx context.Context, mongoDatabase *mongo.Database, appID primitive.ObjectID, version, owner string, artifacts []model.Artifact) {
	collection := mongoDatabase.Collection("apps")
	for _, artifact := range artifacts {
		filter := bson.D{
			{Key: "app_id", Value: appID},
			{Key: "version", Value: version},
			{Key: "owner", Value: owner},
			{Key: "artifacts", Value: bson.D{
				{Key: "$elemMatch", Value: bson.D{
					{Key: "link", Value: artifact.Link},
					{Key: "platform", Value: artifact.Platform},
					{Key: "arch", Value: artifact.Arch},
					{Key: "package", Value: artifact.Package},
				}},
			}},
		}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "artifacts.$.hashes_verified", Value: true}}}}
		if _, err := collection.UpdateOne(ctx, filter, update); err != nil {
			logrus.Errorf("Failed to mark artifact hashes verified: link=%s: %v", artifact.Link, err)
		}
	}
}
