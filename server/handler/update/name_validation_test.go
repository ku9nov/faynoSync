package update

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"faynoSync/mongod"
	"faynoSync/server/handler/create"
	"faynoSync/server/model"
	"faynoSync/server/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// The app name becomes the leading segment of public-bucket keys, so '/' would
// let one tenant place objects under another tenant's prefix (e.g. tuf_metadata/<victim>/<app>/).
const prefixEscapingAppName = "tuf_metadata/vic/vapp/x"

type nameFixture struct {
	repo  mongod.AppRepository
	db    *mongo.Database
	owner string
	ctx   context.Context
}

func newNameFixture(t *testing.T) nameFixture {
	t.Helper()
	repo, db := testRepository(t)
	owner := "namecheck" + primitive.NewObjectID().Hex()[16:]
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.Collection("apps_meta").DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = db.Collection("apps").DeleteMany(ctx, bson.M{"owner": owner})
	})
	return nameFixture{repo: repo, db: db, owner: owner,
		ctx: utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalAdmin, Username: owner})}
}

func (f nameFixture) post(t *testing.T, handler gin.HandlerFunc, data any, files map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	require.NoError(t, mw.WriteField("data", string(raw)))
	for name, content := range files {
		part, err := mw.CreateFormFile("file", name)
		require.NoError(t, err)
		_, err = part.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, mw.Close())

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/", func(c *gin.Context) {
		c.Set("username", f.owner)
		c.Request = c.Request.WithContext(f.ctx)
	}, handler)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	router.ServeHTTP(w, req)
	return w
}

func (f nameFixture) appCount(t *testing.T, name string) int64 {
	t.Helper()
	n, err := f.db.Collection("apps_meta").CountDocuments(context.Background(), bson.M{"app_name": name, "owner": f.owner})
	require.NoError(t, err)
	return n
}

// To verify: In CreateItem skip utils.ValidateItemName for the app branch; test will fail (app created).
func TestCreateApp_NameWithSlash_Rejected(t *testing.T) {
	f := newNameFixture(t)
	s3 := useFakeS3(t)

	w := f.post(t, func(c *gin.Context) { create.CreateApp(c, f.repo) },
		map[string]string{"app": prefixEscapingAppName}, map[string]string{"logo.json": "{}"})

	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Zero(t, f.appCount(t, prefixEscapingAppName))
	assert.Empty(t, s3.written(), "no logo may be written for a rejected app name")
}

// To verify: In UpdateItem skip utils.ValidateItemName for the app branch; test will fail (app renamed).
func TestUpdateApp_RenameWithSlash_Rejected(t *testing.T) {
	f := newNameFixture(t)
	s3 := useFakeS3(t)
	name := "renamecheck" + f.owner
	id, err := f.repo.CreateApp(name, "", "", false, "", false, false, false, f.owner, f.ctx)
	require.NoError(t, err)

	w := f.post(t, func(c *gin.Context) { UpdateApp(c, f.repo) },
		map[string]string{"id": id.(primitive.ObjectID).Hex(), "app": prefixEscapingAppName}, map[string]string{"logo.json": "{}"})

	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Equal(t, int64(1), f.appCount(t, name), "app must keep its name")
	assert.Empty(t, s3.written(), "no logo may be written for a rejected app name")
}

// /apps/update must reject key components that /upload rejects, before anything is written.
// To verify: In validateUpdateCommonParams check only platform and arch; test will fail (object written).
func TestUpdateSpecificApp_UnsafeKeyComponents_Rejected(t *testing.T) {
	f := newNameFixture(t)
	appName := "keycheck" + f.owner
	_, err := f.repo.CreateApp(appName, "", "", false, "", false, false, false, f.owner, f.ctx)
	require.NoError(t, err)
	_, err = f.repo.CreateChannel("stable", f.owner, f.ctx)
	require.NoError(t, err)
	_, err = f.repo.CreatePlatform("linux", []model.Updater{{Type: "manual", Default: true}}, f.owner, f.ctx)
	require.NoError(t, err)
	_, err = f.repo.CreateArch("x64", f.owner, f.ctx)
	require.NoError(t, err)

	// A name stored before validation existed; /apps/update must not build keys from it.
	legacyApp := prefixEscapingAppName + f.owner
	_, err = f.db.Collection("apps_meta").InsertOne(context.Background(), bson.M{"app_name": legacyApp, "owner": f.owner, "private": false})
	require.NoError(t, err)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	base := map[string]string{"app_name": appName, "version": "1.0.0", "channel": "stable", "platform": "linux", "arch": "x64"}
	cases := map[string]map[string]string{
		"channel with dot-segments": {"channel": "../keycheckvictim-vic/stable"},
		"version with slash":        {"version": "1.0.0/../../x"},
		"unknown channel":           {"channel": "nosuchchannel"},
		"app name with slash":       {"app_name": legacyApp},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			s3 := useFakeS3(t)
			data := map[string]string{"id": primitive.NewObjectID().Hex()}
			for k, v := range base {
				data[k] = v
			}
			for k, v := range override {
				data[k] = v
			}

			w := f.post(t, func(c *gin.Context) { UpdateSpecificApp(c, f.repo, f.db, rdb, false) },
				data, map[string]string{"app.exe": "attacker-marker"})

			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Empty(t, s3.written(), "no object may be written for an invalid key component")
		})
	}
}
