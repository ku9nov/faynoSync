package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"faynoSync/server/handler/info"
	"faynoSync/server/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Withdrawing an artifact must stop cached /checkVersion responses from advertising it,
// as DELETE /apps/delete already does.
// To verify: In DeleteSpecificArtifactOfApp skip create.InvalidateAppCaches; test will fail (cache key kept).
func TestDeleteSpecificArtifact_InvalidatesResponseCache(t *testing.T) {
	f := newHandlerFixture(t, true)
	ctx := context.Background()
	appName := f.owner + "app"
	appID := f.createApp(t, appName)
	channelID, err := f.repo.CreateChannel("stable", f.owner, f.ctx)
	require.NoError(t, err)
	platformID, err := f.repo.CreatePlatform("linux", []model.Updater{{Type: "manual", Default: true}}, f.owner, f.ctx)
	require.NoError(t, err)
	archID, err := f.repo.CreateArch("x64", f.owner, f.ctx)
	require.NoError(t, err)
	versionID := primitive.NewObjectID()
	_, err = f.db.Collection("apps").InsertOne(ctx, bson.M{
		"_id": versionID, "app_id": appID, "owner": f.owner, "version": "1.0.0", "channel_id": channelID,
		"published": true, "updated_at": time.Now(),
		"artifacts": bson.A{bson.M{"link": "http://storage.invalid/withdrawn.bin", "platform": platformID, "arch": archID}},
	})
	require.NoError(t, err)

	cacheKey := info.CreateCacheKey(map[string]interface{}{
		"owner": f.owner, "app_name": appName, "version": "0.9.0", "channel": "stable", "platform": "linux", "arch": "x64",
	})
	require.NoError(t, f.rdb.Set(ctx, cacheKey, `{"update_available":true}`, time.Hour).Err())

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	data, err := json.Marshal(map[string]any{
		"id": versionID.Hex(), "app_name": appName, "version": "1.0.0", "channel": "stable", "artifacts_to_delete": []string{"0"},
	})
	require.NoError(t, err)
	require.NoError(t, mw.WriteField("data", string(data)))
	require.NoError(t, mw.Close())
	router := gin.New()
	router.POST("/artifact/delete", func(c *gin.Context) {
		c.Set("username", f.owner)
		c.Request = c.Request.WithContext(f.ctx)
	}, f.handler.DeleteSpecificArtifactOfApp)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/artifact/delete", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var stored struct {
		Artifacts []bson.M `bson:"artifacts"`
	}
	require.NoError(t, f.db.Collection("apps").FindOne(ctx, bson.M{"_id": versionID}).Decode(&stored))
	require.Empty(t, stored.Artifacts, "precondition: the artifact is removed")
	exists, err := f.rdb.Exists(ctx, cacheKey).Result()
	require.NoError(t, err)
	assert.Zero(t, exists, "cached response for the app's channel must be invalidated")
}
