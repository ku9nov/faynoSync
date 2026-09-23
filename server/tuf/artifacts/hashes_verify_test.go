package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"faynoSync/server/model"
	"faynoSync/server/utils/storage"

	"github.com/spf13/viper"
)

type fakeObject struct {
	body         []byte
	storedSHA256 string
}

type fakeHashSource struct {
	objects map[string]fakeObject
	opened  []string
}

func (f *fakeHashSource) StatObject(_ context.Context, bucket, key string) (storage.ObjectStat, error) {
	obj, ok := f.objects[bucket+"/"+key]
	if !ok {
		return storage.ObjectStat{}, storage.ErrObjectNotFound
	}
	return storage.ObjectStat{Size: int64(len(obj.body)), SHA256: obj.storedSHA256}, nil
}

func (f *fakeHashSource) OpenObject(_ context.Context, bucket, key string) (io.ReadCloser, error) {
	f.opened = append(f.opened, key)
	obj, ok := f.objects[bucket+"/"+key]
	if !ok {
		return nil, storage.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(obj.body)), nil
}

var testPayload = []byte("stored artifact bytes")

func hexSHA256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func hexSHA512(b []byte) string { s := sha512.Sum512(b); return hex.EncodeToString(s[:]) }

func declaredArtifact(link string, body []byte) model.Artifact {
	return model.Artifact{
		Link:   link,
		Length: int64(len(body)),
		Hashes: map[string]string{"sha256": hexSHA256(body), "sha512": hexSHA512(body)},
	}
}

func TestVerifyArtifactHashes(t *testing.T) {
	other := []byte("different bytes, same size!")[:len(testPayload)]

	cases := []struct {
		name       string
		object     fakeObject
		artifact   model.Artifact
		wantErr    string
		wantStream bool
	}{
		{
			name:     "storage sha256 matches, no stream",
			object:   fakeObject{body: testPayload, storedSHA256: hexSHA256(testPayload)},
			artifact: declaredArtifact("", testPayload),
		},
		{
			name:     "storage sha256 differs",
			object:   fakeObject{body: testPayload, storedSHA256: hexSHA256(other)},
			artifact: declaredArtifact("", testPayload),
			wantErr:  "sha256 mismatch",
		},
		{
			name:       "streamed hashes match",
			object:     fakeObject{body: testPayload},
			artifact:   declaredArtifact("", testPayload),
			wantStream: true,
		},
		{
			name:   "declared hex is case-insensitive",
			object: fakeObject{body: testPayload},
			artifact: model.Artifact{
				Length: int64(len(testPayload)),
				Hashes: map[string]string{"sha256": strings.ToUpper(hexSHA256(testPayload))},
			},
			wantStream: true,
		},
		{
			name:       "streamed bytes differ",
			object:     fakeObject{body: other},
			artifact:   declaredArtifact("", testPayload),
			wantErr:    "sha256 mismatch",
			wantStream: true,
		},
		{
			name:   "streamed sha512 differs",
			object: fakeObject{body: testPayload},
			artifact: model.Artifact{
				Length: int64(len(testPayload)),
				Hashes: map[string]string{"sha256": hexSHA256(testPayload), "sha512": hexSHA512(other)},
			},
			wantErr:    "sha512 mismatch",
			wantStream: true,
		},
		{
			name:   "length differs",
			object: fakeObject{body: testPayload, storedSHA256: hexSHA256(testPayload)},
			artifact: model.Artifact{
				Length: int64(len(testPayload)) + 1,
				Hashes: map[string]string{"sha256": hexSHA256(testPayload)},
			},
			wantErr: "length",
		},
		{
			name:     "no sha256 declared",
			object:   fakeObject{body: testPayload},
			artifact: model.Artifact{Length: int64(len(testPayload)), Hashes: map[string]string{"sha512": hexSHA512(testPayload)}},
			wantErr:  "no sha256",
		},
		{
			name:   "unknown algorithm cannot be verified",
			object: fakeObject{body: testPayload, storedSHA256: hexSHA256(testPayload)},
			artifact: model.Artifact{
				Length: int64(len(testPayload)),
				Hashes: map[string]string{"sha256": hexSHA256(testPayload), "md5": "00"},
			},
			wantErr: "unsupported hash algorithm",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := &fakeHashSource{objects: map[string]fakeObject{"bucket/key": tc.object}}
			err := verifyArtifactHashes(context.Background(), source, "bucket", "key", tc.artifact)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if streamed := len(source.opened) > 0; streamed != tc.wantStream {
				t.Errorf("streamed = %v, want %v", streamed, tc.wantStream)
			}
		})
	}
}

func TestVerifyArtifactHashesMissingObject(t *testing.T) {
	source := &fakeHashSource{objects: map[string]fakeObject{}}
	err := verifyArtifactHashes(context.Background(), source, "bucket", "key", declaredArtifact("", testPayload))
	if !errors.Is(err, storage.ErrObjectNotFound) {
		t.Fatalf("error = %v, want ErrObjectNotFound", err)
	}
}

func withHashSource(t *testing.T, source objectHashSource, sourceErr error) *int {
	t.Helper()
	calls := 0
	original := newObjectHashSource
	newObjectHashSource = func(*viper.Viper) (objectHashSource, error) {
		calls++
		return source, sourceErr
	}
	t.Cleanup(func() { newObjectHashSource = original })
	return &calls
}

func hashVerifyEnv() *viper.Viper {
	env := viper.New()
	env.Set("API_URL", "https://api.example.com")
	env.Set("S3_ENDPOINT", "https://public.example.com")
	env.Set("S3_BUCKET_NAME", "public")
	env.Set("S3_BUCKET_NAME_PRIVATE", "private")
	return env
}

func TestVerifyUnverifiedArtifactsSkipsServerHashed(t *testing.T) {
	calls := withHashSource(t, nil, errors.New("must not be created"))

	artifact := declaredArtifact("https://api.example.com/download?key=app/a.exe", testPayload)
	artifact.HashesVerified = true

	verified, err := verifyUnverifiedArtifacts(context.Background(), hashVerifyEnv(), []model.Artifact{artifact})
	if err != nil || len(verified) != 0 || *calls != 0 {
		t.Fatalf("verified=%v err=%v storage calls=%d, want nothing touched", verified, err, *calls)
	}
}

func TestVerifyUnverifiedArtifactsUsesBucketByVisibility(t *testing.T) {
	source := &fakeHashSource{objects: map[string]fakeObject{
		"private/app/a.exe": {body: testPayload},
		"public/app/b.exe":  {body: testPayload},
	}}
	withHashSource(t, source, nil)

	artifacts := []model.Artifact{
		declaredArtifact("https://api.example.com/download?key=app/a.exe", testPayload),
		declaredArtifact("https://public.example.com/app/b.exe", testPayload),
	}
	verified, err := verifyUnverifiedArtifacts(context.Background(), hashVerifyEnv(), artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("verified %d artifacts, want 2", len(verified))
	}
}

func TestVerifyUnverifiedArtifactsRejectsWholePublish(t *testing.T) {
	source := &fakeHashSource{objects: map[string]fakeObject{
		"private/app/good.exe": {body: testPayload},
		"private/app/bad.exe":  {body: []byte("tampered bytes here!!")},
	}}
	withHashSource(t, source, nil)

	artifacts := []model.Artifact{
		declaredArtifact("https://api.example.com/download?key=app/good.exe", testPayload),
		declaredArtifact("https://api.example.com/download?key=app/bad.exe", testPayload),
	}
	verified, err := verifyUnverifiedArtifacts(context.Background(), hashVerifyEnv(), artifacts)
	if err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if verified != nil {
		t.Errorf("verified = %v, want none marked when the publish is rejected", verified)
	}
	if !strings.Contains(err.Error(), "app/bad.exe") || strings.Contains(err.Error(), "app/good.exe") {
		t.Errorf("error %q should name only the failing artifact", err)
	}
}

func TestVerifyUnverifiedArtifactsFailsWithoutReadableStorage(t *testing.T) {
	withHashSource(t, nil, errors.New("storage driver \"minio\" cannot read back stored objects"))

	_, err := verifyUnverifiedArtifacts(context.Background(), hashVerifyEnv(),
		[]model.Artifact{declaredArtifact("https://api.example.com/download?key=app/a.exe", testPayload)})
	if err == nil {
		t.Fatal("unverifiable artifact accepted")
	}
}
