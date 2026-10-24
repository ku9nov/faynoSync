package artifacts

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"faynoSync/server/model"
	"faynoSync/server/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type teamScopeFixture struct {
	db          *mongo.Database
	redis       *redis.Client
	teamUser    string
	allowedApp  primitive.ObjectID
	foreignApp  primitive.ObjectID
	foreignVers primitive.ObjectID
	foreignName string
}

// Admin owns apps X and Y; team user has apps.edit and is restricted to X.
func newTeamScopeFixture(t *testing.T, foreignSigned bool) teamScopeFixture {
	t.Helper()
	db := mongoTestDB(t)
	ctx := context.Background()
	suffix := primitive.NewObjectID().Hex()
	owner := "scope-admin-" + suffix
	teamUser := "scope-team-" + suffix
	appX, appY, versY := primitive.NewObjectID(), primitive.NewObjectID(), primitive.NewObjectID()

	_, err := db.Collection("admins").InsertOne(ctx, bson.M{"username": owner})
	require.NoError(t, err)
	_, err = db.Collection("team_users").InsertOne(ctx, bson.M{
		"_id": primitive.NewObjectID(), "username": teamUser, "owner": owner,
		"permissions": bson.M{"apps": bson.M{"edit": true, "allowed": []string{appX.Hex()}}},
	})
	require.NoError(t, err)
	_, err = db.Collection("apps_meta").InsertMany(ctx, []any{
		bson.M{"_id": appX, "app_name": "scopex" + suffix, "owner": owner},
		bson.M{"_id": appY, "app_name": "scopey" + suffix, "owner": owner},
	})
	require.NoError(t, err)
	_, err = db.Collection("apps").InsertOne(ctx, bson.M{
		"_id": versY, "app_id": appY, "version": "1.0.0", "owner": owner,
		"artifacts": []model.Artifact{{
			Link:           "http://api.example.com/download?key=scopey%2F1.0.0%2Ffile.bin",
			Hashes:         map[string]string{"sha256": "abc"},
			Length:         100,
			HashesVerified: true,
			TufSigned:      foreignSigned,
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": owner})
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = db.Collection("apps_meta").DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = db.Collection("apps").DeleteMany(ctx, bson.M{"owner": owner})
	})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	t.Cleanup(func() { viper.GetViper().Set("API_URL", oldAPI) })

	mr := miniredis.RunT(t)
	return teamScopeFixture{
		db: db, redis: redis.NewClient(&redis.Options{Addr: mr.Addr()}),
		teamUser: teamUser, allowedApp: appX, foreignApp: appY, foreignVers: versY, foreignName: "scopey" + suffix,
	}
}

// Same middleware chain as tuf.SetupRoutes, authenticated as the team user.
func (f teamScopeFixture) serve(t *testing.T, path string, handler func(*gin.Context), payload any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(path,
		func(c *gin.Context) { c.Set("username", f.teamUser) },
		utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, f.db),
		utils.ResolveOwnerMiddleware(f.db),
		handler,
	)
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var body struct {
		Data struct {
			TaskID string `json:"task_id"`
		} `json:"data"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) == nil && body.Data.TaskID != "" {
		waitForTaskTerminalState(t, f.redis, body.Data.TaskID, 5*time.Second)
	}
	return w
}

// To verify: In PostPublishArtifacts skip the team user allowed-apps check; test will fail (202 instead of 403).
func TestPostPublishArtifacts_TeamUserOutsideAllowedApps_Forbidden(t *testing.T) {
	f := newTeamScopeFixture(t, false)

	w := f.serve(t, "/tuf/v1/artifacts/publish", func(c *gin.Context) { PostPublishArtifacts(c, f.redis, f.db) },
		PublishArtifactsPayload{AppID: f.foreignApp.Hex(), Version: "1.0.0"})

	assert.Equal(t, http.StatusForbidden, w.Code, "team user restricted to another app must not publish app Y: %s", w.Body.String())
}

// To verify: In PostDeleteArtifacts skip the team user allowed-apps check; test will fail (202 instead of 403).
func TestPostDeleteArtifacts_TeamUserOutsideAllowedApps_Forbidden(t *testing.T) {
	f := newTeamScopeFixture(t, true)

	w := f.serve(t, "/tuf/v1/artifacts/delete", func(c *gin.Context) { PostDeleteArtifacts(c, f.redis, f.db) },
		DeleteArtifactsPayload{AppID: f.foreignVers.Hex(), AppName: f.foreignName, Version: "1.0.0", ArtifactsToDelete: []string{"0"}})

	assert.Equal(t, http.StatusForbidden, w.Code, "team user restricted to another app must not remove app Y targets: %s", w.Body.String())
}
