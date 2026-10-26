package utils_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"faynoSync/mongod"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// An admin and a team user sharing one name (signup/team-create race, or data from
// before the uniqueness check). Each session must stay inside its own principal.
type collisionEnv struct {
	router      *gin.Engine
	attacker    string
	victim      string
	adminToken  string
	teamToken   string
	victimAppID primitive.ObjectID
}

func newCollisionEnv(t *testing.T) collisionEnv {
	t.Helper()
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)
	repo := mongod.NewAppRepository(&configDB, client)

	oldSecret := viper.GetViper().GetString("JWT_SECRET")
	viper.GetViper().Set("JWT_SECRET", "collision-test-secret")
	t.Cleanup(func() { viper.GetViper().Set("JWT_SECRET", oldSecret) })

	ctx := context.Background()
	suffix := primitive.NewObjectID().Hex()[16:]
	env := collisionEnv{attacker: "colattacker" + suffix, victim: "colvictim" + suffix, victimAppID: primitive.NewObjectID()}
	victimAdminID, teamID := primitive.NewObjectID(), primitive.NewObjectID()
	_, err := db.Collection("admins").InsertMany(ctx, []any{
		bson.M{"username": env.attacker, "password": "x"},
		bson.M{"_id": victimAdminID, "username": env.victim, "password": "x"},
	})
	require.NoError(t, err)
	_, err = db.Collection("team_users").InsertOne(ctx, bson.M{
		"_id": teamID, "username": env.victim, "owner": env.attacker, "password": "x",
		"permissions": bson.M{"apps": bson.M{"allowed": []string{}}},
	})
	require.NoError(t, err)
	_, err = db.Collection("apps_meta").InsertOne(ctx, bson.M{"_id": env.victimAppID, "app_name": "colapp" + suffix, "owner": env.victim})
	require.NoError(t, err)
	t.Cleanup(func() {
		names := bson.M{"$in": []string{env.attacker, env.victim}}
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": names})
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": names})
		_, _ = db.Collection("apps_meta").DeleteMany(ctx, bson.M{"owner": names})
	})

	env.adminToken, err = utils.GenerateSessionJWT(victimAdminID, utils.PrincipalAdmin, 0, env.victim)
	require.NoError(t, err)
	env.teamToken, err = utils.GenerateSessionJWT(teamID, utils.PrincipalTeam, 0, env.victim)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	auth := utils.AuthMiddleware(db)
	r.GET("/admin", auth, utils.AdminOnlyMiddleware(db), func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/perm", auth, utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, db), func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/owner", auth, utils.ResolveOwnerMiddleware(db), func(c *gin.Context) {
		owner, err := utils.GetOwnerFromContext(c)
		require.NoError(t, err)
		c.String(http.StatusOK, owner)
	})
	r.GET("/app", auth, func(c *gin.Context) {
		username, _ := utils.GetUsernameFromContext(c)
		app, err := repo.GetAppByID(env.victimAppID, username, c.Request.Context())
		if err != nil {
			c.String(http.StatusForbidden, err.Error())
			return
		}
		c.String(http.StatusOK, app.Owner)
	})
	env.router = r
	return env
}

func (e collisionEnv) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	e.router.ServeHTTP(w, req)
	return w
}

// To verify: In AdminOnlyMiddleware look the caller up in admins by username; test will fail (/admin 200).
func TestTeamSession_NameCollidesWithAdmin_StaysTeamUser(t *testing.T) {
	e := newCollisionEnv(t)

	assert.Equal(t, http.StatusForbidden, e.get(t, "/admin", e.teamToken).Code, "team-typed session must not pass admin-only routes")
	assert.Equal(t, http.StatusForbidden, e.get(t, "/perm", e.teamToken).Code, "team-typed session must get its own (empty) permissions, not the admin's")

	w := e.get(t, "/owner", e.teamToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, e.attacker, w.Body.String(), "team-typed session must resolve to its own admin")

	assert.Equal(t, http.StatusForbidden, e.get(t, "/app", e.teamToken).Code, "team-typed session must not reach the colliding admin's app")
}

// To verify: In ResolveRequestOwner or the repository look team_users up by username first; test will fail (owner is the attacker).
func TestAdminSession_NameCollidesWithTeamUser_StaysAdmin(t *testing.T) {
	e := newCollisionEnv(t)

	assert.Equal(t, http.StatusOK, e.get(t, "/admin", e.adminToken).Code)
	assert.Equal(t, http.StatusOK, e.get(t, "/perm", e.adminToken).Code, "admin must not get the colliding team user's permissions")

	w := e.get(t, "/owner", e.adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, e.victim, w.Body.String(), "admin-typed session must resolve to its own tenant")

	w = e.get(t, "/app", e.adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, e.victim, w.Body.String())
}

// To verify: In CallerTeamUser fall back to an admin when no principal is in the context; test will fail (no error).
func TestResolveRequestOwner_WithoutPrincipal_Denies(t *testing.T) {
	_, err := utils.ResolveRequestOwner(context.Background(), "anyone", nil)
	assert.Error(t, err)
}
