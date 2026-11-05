package artifacts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"faynoSync/mongod"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 404 versus 403 must not tell a team user which versions exist in apps outside their grant.
// To verify: In PostPublishArtifacts look up the version before ensureAppAccessByID; test will fail (404).
func TestPostPublishArtifacts_TeamUserNonexistentVersionOutsideGrant_Forbidden(t *testing.T) {
	f := newTeamScopeFixture(t, false)
	publish := func(c *gin.Context) { PostPublishArtifacts(c, f.redis, f.db) }

	w := f.serve(t, "/tuf/v1/artifacts/publish", publish, PublishArtifactsPayload{AppID: f.foreignApp.Hex(), Version: "9.9.9"})
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = f.serve(t, "/tuf/v1/artifacts/publish", publish, PublishArtifactsPayload{AppID: primitive.NewObjectID().Hex(), Version: "9.9.9"})
	assert.Equal(t, http.StatusForbidden, w.Code, "unknown app: %s", w.Body.String())

	w = f.serve(t, "/tuf/v1/artifacts/publish", publish, PublishArtifactsPayload{AppID: f.allowedApp.Hex(), Version: "9.9.9"})
	assert.Equal(t, http.StatusNotFound, w.Code, "granted app keeps 404: %s", w.Body.String())
}

// To verify: In PostDeleteArtifacts match the version before ensureAppAccessByID; test will fail (404).
func TestPostDeleteArtifacts_TeamUserNonexistentVersionOutsideGrant_Forbidden(t *testing.T) {
	f := newTeamScopeFixture(t, true)
	remove := func(c *gin.Context) { PostDeleteArtifacts(c, f.redis, f.db) }

	w := f.serve(t, "/tuf/v1/artifacts/delete", remove,
		DeleteArtifactsPayload{AppID: f.foreignVers.Hex(), AppName: f.foreignName, Version: "9.9.9", ArtifactsToDelete: []string{"0"}})
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = f.serve(t, "/tuf/v1/artifacts/delete", remove,
		DeleteArtifactsPayload{AppID: primitive.NewObjectID().Hex(), AppName: f.foreignName, Version: "9.9.9", ArtifactsToDelete: []string{"0"}})
	assert.Equal(t, http.StatusForbidden, w.Code, "unknown version id: %s", w.Body.String())
}

// To verify: In ensureAppAccess answer err.Error() with 403; test will fail (403 with driver text).
func TestEnsureAppAccess_DatabaseError_InternalWithoutDetails(t *testing.T) {
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	require.NoError(t, client.Disconnect(context.Background()))
	db := client.Database(configDB.Database)

	principal := utils.Principal{Type: utils.PrincipalTeam, ID: primitive.NewObjectID(), Username: "dberr-team"}
	ctx := utils.WithPrincipal(context.Background(), principal)
	dbErr := utils.EnsureTeamUserAppAccess(ctx, "app", db)
	require.Error(t, dbErr)
	uploadErr := utils.EnsureTeamUserUploadAccess(ctx, map[string]interface{}{"app_name": "app"}, db)
	require.Error(t, uploadErr)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/artifacts/publish", nil).WithContext(ctx)
	c.Set("username", principal.Username)

	require.Error(t, ensureAppAccess(c, "app", db))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), dbErr.Error())
	assert.JSONEq(t, `{"error":"failed to check access"}`, w.Body.String())

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	utils.RespondTeamAccessError(c, uploadErr)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), uploadErr.Error())
}

// A real denial keeps 403 and its message.
func TestEnsureAppAccess_Denied_Forbidden(t *testing.T) {
	f := newTeamScopeFixture(t, false)
	var u struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	require.NoError(t, f.db.Collection("team_users").FindOne(context.Background(), bson.M{"username": f.teamUser}).Decode(&u))
	ctx := utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalTeam, ID: u.ID, Username: f.teamUser})

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/artifacts/publish", nil).WithContext(ctx)
	c.Set("username", f.teamUser)

	require.Error(t, ensureAppAccess(c, f.foreignName, f.db))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"error":"you don't have access to this app"}`, w.Body.String())
}
