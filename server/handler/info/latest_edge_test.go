package info

import (
	"context"
	"io"
	"mime/multipart"
	"testing"
	"time"

	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type cdnUpload struct {
	key  string
	body string
}

type blockingCDNClient struct {
	utils.StorageClient
	release chan struct{}
	uploads chan cdnUpload
}

func (b *blockingCDNClient) GetObjectETag(ctx context.Context, bucketName, objectKey string) (string, bool, error) {
	<-b.release
	return "", false, nil
}

func (b *blockingCDNClient) UploadPublicObjectWithCacheControl(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType, cacheControl string) (string, error) {
	body, _ := io.ReadAll(fileReader)
	b.uploads <- cdnUpload{key: objectKey, body: string(body)}
	return "", nil
}

func withCDNClient(t *testing.T, client utils.StorageClient) {
	t.Helper()
	viper.Set("S3_BUCKET_NAME_CDN", "cdn-bucket")
	cdnClientMu.Lock()
	cdnClient = client
	cdnClientMu.Unlock()
	t.Cleanup(func() {
		viper.Set("S3_BUCKET_NAME_CDN", "")
		cdnClientMu.Lock()
		cdnClient = nil
		cdnClientMu.Unlock()
	})
}

func cdnTestParams() map[string]interface{} {
	return map[string]interface{}{
		"owner": "admin", "app_name": "app", "channel": "stable", "platform": "darwin", "arch": "arm64", "updater": "manual", "version": "1.0.0",
	}
}

func TestPublishResponseToCDNDoesNotWaitForStorage(t *testing.T) {
	client := &blockingCDNClient{release: make(chan struct{}), uploads: make(chan cdnUpload, 1)}
	withCDNClient(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		publishResponseToCDN(ctx, cdnTestParams(), gin.H{"update_available": true})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publishResponseToCDN blocked on storage")
	}

	// The request context ends with the response; the background publish must survive it.
	cancel()
	close(client.release)

	select {
	case upload := <-client.uploads:
		if upload.key != "responses/admin/app/stable/darwin/arm64/manual/1.0.0.json" {
			t.Fatalf("unexpected key %q", upload.key)
		}
		if upload.body != `{"update_available":true}` {
			t.Fatalf("unexpected body %q", upload.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response was never published to CDN")
	}
}

func TestPublishResponseToCDNPublishesSynchronouslyWhenSlotsAreBusy(t *testing.T) {
	client := &blockingCDNClient{release: make(chan struct{}), uploads: make(chan cdnUpload, 1)}
	close(client.release)
	withCDNClient(t, client)

	for i := 0; i < cap(cdnPublishSlots); i++ {
		cdnPublishSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(cdnPublishSlots); i++ {
			<-cdnPublishSlots
		}
	})

	publishResponseToCDN(context.Background(), cdnTestParams(), gin.H{"update_available": false})

	select {
	case upload := <-client.uploads:
		if upload.body != `{"update_available":false}` {
			t.Fatalf("unexpected body %q", upload.body)
		}
	default:
		t.Fatal("publish did not complete before returning")
	}
}
