package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"faynoSync/mongod"
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

type handlerFixture struct {
	handler AppHandler
	repo    mongod.AppRepository
	db      *mongo.Database
	rdb     *redis.Client
	owner   string
	ctx     context.Context
}

func newHandlerFixture(t *testing.T, performanceMode bool) handlerFixture {
	t.Helper()
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)
	repo := mongod.NewAppRepository(&configDB, client)
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})

	owner := "hfix" + primitive.NewObjectID().Hex()[16:]
	t.Cleanup(func() {
		ctx := context.Background()
		for _, coll := range []string{"apps_meta", "apps", "api_tokens"} {
			_, _ = db.Collection(coll).DeleteMany(ctx, bson.M{"owner": owner})
		}
	})
	gin.SetMode(gin.TestMode)
	return handlerFixture{
		handler: NewAppHandler(client, repo, db, rdb, performanceMode),
		repo:    repo, db: db, rdb: rdb, owner: owner,
		ctx: utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalAdmin, Username: owner}),
	}
}

func (f handlerFixture) createApp(t *testing.T, name string) primitive.ObjectID {
	t.Helper()
	id, err := f.repo.CreateApp(name, "", "", false, "", false, false, false, f.owner, f.ctx)
	require.NoError(t, err)
	return id.(primitive.ObjectID)
}

func (f handlerFixture) apiToken(t *testing.T, allowedApps ...primitive.ObjectID) string {
	t.Helper()
	token, prefix, hash, err := utils.GenerateAPIToken()
	require.NoError(t, err)
	allowed := make([]string, 0, len(allowedApps))
	for _, id := range allowedApps {
		allowed = append(allowed, id.Hex())
	}
	_, err = f.db.Collection("api_tokens").InsertOne(context.Background(), bson.M{
		"_id": primitive.NewObjectID(), "name": "ci", "token_hash": hash, "token_prefix": prefix,
		"owner": f.owner, "allowed_apps": allowed, "created_at": time.Now(),
	})
	require.NoError(t, err)
	return token
}

// get runs a request through AuthMiddleware the way every route after router.Use(authMiddleware) does.
func (f handlerFixture) get(t *testing.T, path, token string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET("/*any", utils.AuthMiddleware(f.db), handler)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	return w
}

// An fns_ token scoped to app X may not read versions, changelogs or private links of app Y.
// To verify: In /search treat an API token as the full tenant admin; test will fail (200 for Y).
func TestSearch_APITokenOutsideAllowedApps_Forbidden(t *testing.T) {
	f := newHandlerFixture(t, false)
	appX, appY := f.owner+"x", f.owner+"y"
	idX := f.createApp(t, appX)
	idY := f.createApp(t, appY)
	_, err := f.db.Collection("apps").InsertOne(context.Background(), bson.M{
		"app_id": idY, "owner": f.owner, "version": "1.0.0", "published": false, "artifacts": bson.A{},
	})
	require.NoError(t, err)
	token := f.apiToken(t, idX)

	w := f.get(t, "/search?app_name="+appY, token, f.handler.GetAppByName)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = f.get(t, "/search?app_name="+appX, token, f.handler.GetAppByName)
	assert.Equal(t, http.StatusOK, w.Code, "the token's own app must stay readable: %s", w.Body.String())
}

// Telemetry covers the whole tenant, which is beyond an app-scoped upload token.
// To verify: In /telemetry resolve an API token to its owner's statistics; test will fail (200).
func TestTelemetry_APIToken_Forbidden(t *testing.T) {
	f := newHandlerFixture(t, false)
	token := f.apiToken(t, f.createApp(t, f.owner+"x"))

	w := f.get(t, "/telemetry?range=week", token, f.handler.GetTelemetry)

	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
