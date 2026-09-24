//go:build storagelive

package storage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func liveEnv(t *testing.T) *viper.Viper {
	t.Helper()
	env := viper.New()
	env.SetConfigType("env")
	env.SetConfigName(".env")
	env.AddConfigPath("../../..")
	if err := env.ReadInConfig(); err != nil {
		t.Logf(".env not read (%v), falling back to process environment", err)
	}
	env.AutomaticEnv()
	return env
}

func s3ErrorCode(body []byte) string {
	s := string(body)
	start := strings.Index(s, "<Code>")
	if start < 0 {
		if len(s) > 200 {
			return s[:200]
		}
		return s
	}
	end := strings.Index(s[start:], "</Code>")
	if end < 0 {
		return "?"
	}
	return s[start+len("<Code>") : start+end]
}

func putSigned(t *testing.T, url string, headers map[string][]string, body []byte) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for name, values := range headers {
		for _, v := range values {
			req.Header.Set(name, v)
		}
	}
	req.ContentLength = int64(len(body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	code := ""
	if resp.StatusCode >= 300 {
		code = s3ErrorCode(respBody)
	}
	return resp.StatusCode, code
}

// Same flow complete() and the TUF pre-sign check will use, through the production methods.
func TestPresignedUploaderLive(t *testing.T) {
	env := liveEnv(t)
	bucket := env.GetString("S3_BUCKET_NAME")

	storageClient, err := NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		t.Fatalf("create storage client: %v", err)
	}
	uploader, ok := storageClient.(PresignedUploader)
	if !ok {
		t.Skipf("driver %q does not support presigned uploads", env.GetString("STORAGE_DRIVER"))
	}

	stamp := time.Now().UnixNano()
	pendingKey := fmt.Sprintf("pending/live-%d/artifact.bin", stamp)
	finalKey := fmt.Sprintf("pending/live-%d/final.bin", stamp)
	payload := []byte("faynoSync presigned upload spike payload")
	md := md5.Sum(payload)
	sha := sha256.Sum256(payload)
	ctx := context.TODO()

	t.Cleanup(func() {
		for _, key := range []string{pendingKey, finalKey} {
			if err := storageClient.DeleteObject(ctx, bucket, key); err != nil {
				t.Logf("cleanup delete %s failed: %v", key, err)
			}
		}
	})

	signed, err := uploader.PresignPutObject(ctx, bucket, pendingKey, md[:], int64(len(payload)), "application/octet-stream", 15*time.Minute)
	if err != nil {
		t.Fatalf("PresignPutObject: %v", err)
	}
	t.Logf("headers the client must send: %v", signed.Headers)

	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0xff
	if status, code := putSigned(t, signed.URL, signed.Headers, tampered); status < 400 {
		t.Fatalf("tampered payload accepted with %d %s", status, code)
	} else {
		t.Logf("PUT tampered -> %d %s", status, code)
	}
	if status, code := putSigned(t, signed.URL, signed.Headers, payload); status >= 300 {
		t.Fatalf("correct payload rejected with %d %s", status, code)
	}

	pending, err := uploader.StatObject(ctx, bucket, pendingKey)
	if err != nil {
		t.Fatalf("StatObject(pending): %v", err)
	}
	t.Logf("pending: %+v", pending)
	if pending.Size != int64(len(payload)) || pending.MD5 != hex.EncodeToString(md[:]) {
		t.Errorf("pending stat %+v does not match the uploaded bytes", pending)
	}

	if err := storageClient.CopyObject(ctx, bucket, pendingKey, finalKey, false); err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	final, err := uploader.StatObject(ctx, bucket, finalKey)
	if err != nil {
		t.Fatalf("StatObject(final): %v", err)
	}
	t.Logf("final: %+v", final)
	if final.SHA256 == "" {
		t.Logf("provider computed no sha256 on copy: TUF pre-sign check must stream the object")
	} else if final.SHA256 != hex.EncodeToString(sha[:]) {
		t.Errorf("final sha256 %s does not match the uploaded bytes", final.SHA256)
	}

	body, err := uploader.OpenObject(ctx, bucket, finalKey)
	if err != nil {
		t.Fatalf("OpenObject: %v", err)
	}
	defer body.Close()
	h := sha256.New()
	if _, err := io.Copy(h, body); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != hex.EncodeToString(sha[:]) {
		t.Errorf("streamed sha256 %s does not match", got)
	}

	if _, err := uploader.StatObject(ctx, bucket, pendingKey+".missing"); err != ErrObjectNotFound {
		t.Errorf("StatObject(missing) = %v, want ErrObjectNotFound", err)
	}
}
