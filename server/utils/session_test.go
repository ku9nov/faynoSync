package utils_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"faynoSync/mongod"
	"faynoSync/server/handler/team"
	"faynoSync/server/handler/update"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type sessionEnv struct {
	db             *mongo.Database
	tenantA        string
	tenantD        string
	tenantAAdminID primitive.ObjectID
}

func newSessionEnv(t *testing.T) sessionEnv {
	t.Helper()
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)

	oldSecret := viper.GetViper().GetString("JWT_SECRET")
	viper.GetViper().Set("JWT_SECRET", "session-test-secret")
	t.Cleanup(func() { viper.GetViper().Set("JWT_SECRET", oldSecret) })

	ctx := context.Background()
	suffix := primitive.NewObjectID().Hex()[16:]
	env := sessionEnv{db: db, tenantA: "sessa" + suffix, tenantD: "sessd" + suffix, tenantAAdminID: primitive.NewObjectID()}
	_, err := db.Collection("admins").InsertMany(ctx, []any{
		bson.M{"_id": env.tenantAAdminID, "username": env.tenantA, "password": "x"},
		bson.M{"username": env.tenantD, "password": "x"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		tenants := []string{env.tenantA, env.tenantD}
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": bson.M{"$in": tenants}})
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": bson.M{"$in": tenants}})
	})
	return env
}

func (e sessionEnv) callAs(t *testing.T, username string, handler func(*gin.Context, *mongo.Database), body any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", username)
	handler(c, e.db)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func (e sessionEnv) createTeamUser(t *testing.T, owner, name string) primitive.ObjectID {
	t.Helper()
	e.callAs(t, owner, team.CreateTeamUser, map[string]any{"username": name, "password": "p", "permissions": map[string]any{"apps": map[string]any{"download": true}}})
	var doc struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	require.NoError(t, e.db.Collection("team_users").FindOne(context.Background(), bson.M{"username": name, "owner": owner}).Decode(&doc))
	return doc.ID
}

// loginToken mints what Login would issue for the principal's current state.
func (e sessionEnv) loginToken(t *testing.T, collection, principalType string, id primitive.ObjectID) string {
	t.Helper()
	var doc struct {
		Username     string `bson:"username"`
		TokenVersion int64  `bson:"token_version"`
	}
	require.NoError(t, e.db.Collection(collection).FindOne(context.Background(), bson.M{"_id": id}).Decode(&doc))
	token, err := utils.GenerateSessionJWT(id, principalType, doc.TokenVersion, doc.Username)
	require.NoError(t, err)
	return token
}

func (e sessionEnv) probe(t *testing.T, token string) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/probe", utils.AuthMiddleware(e.db), func(c *gin.Context) {
		username, _ := utils.GetUsernameFromContext(c)
		c.JSON(http.StatusOK, gin.H{"username": username})
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	var body struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Username
}

func TestSession_CurrentTokenAccepted(t *testing.T) {
	env := newSessionEnv(t)
	name := env.tenantA + "-ci"
	token := env.loginToken(t, "team_users", utils.PrincipalTeam, env.createTeamUser(t, env.tenantA, name))

	code, username := env.probe(t, token)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, name, username)

	code, username = env.probe(t, env.loginToken(t, "admins", utils.PrincipalAdmin, env.tenantAAdminID))
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, env.tenantA, username)
}

func TestSession_LegacyTokenRejected(t *testing.T) {
	env := newSessionEnv(t)
	legacy, err := utils.GenerateJWT(env.tenantA)
	require.NoError(t, err)

	code, _ := env.probe(t, legacy)
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestSession_DeletedTeamUserRecreatedByOtherTenant(t *testing.T) {
	env := newSessionEnv(t)
	name := env.tenantA + "-deploy"
	id := env.createTeamUser(t, env.tenantA, name)
	token := env.loginToken(t, "team_users", utils.PrincipalTeam, id)

	env.callAs(t, env.tenantA, team.DeleteTeamUser, map[string]any{"id": id.Hex()})
	env.createTeamUser(t, env.tenantD, name)

	code, username := env.probe(t, token)
	assert.Equal(t, http.StatusUnauthorized, code, "served as %q", username)
	_, err := utils.SessionUsernameFromJWT(context.Background(), env.db, token)
	assert.Error(t, err, "optional-auth paths must reject the token too")
}

func TestSession_RenamedTeamUserNameReused(t *testing.T) {
	env := newSessionEnv(t)
	name := env.tenantA + "-deploy"
	id := env.createTeamUser(t, env.tenantA, name)
	token := env.loginToken(t, "team_users", utils.PrincipalTeam, id)

	env.callAs(t, env.tenantA, team.UpdateTeamUser, map[string]any{"id": id.Hex(), "username": name + "-old"})
	env.createTeamUser(t, env.tenantD, name)

	code, username := env.probe(t, token)
	assert.Equal(t, http.StatusUnauthorized, code, "served as %q", username)

	code, username = env.probe(t, env.loginToken(t, "team_users", utils.PrincipalTeam, id))
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, name+"-old", username)
}

func TestSession_TeamUserPasswordChangeRevokes(t *testing.T) {
	env := newSessionEnv(t)
	name := env.tenantA + "-ci"
	id := env.createTeamUser(t, env.tenantA, name)
	token := env.loginToken(t, "team_users", utils.PrincipalTeam, id)

	env.callAs(t, env.tenantA, team.UpdateTeamUser, map[string]any{"id": id.Hex(), "username": name, "password": "new"})

	code, _ := env.probe(t, token)
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestSession_TeamUserPermissionChangeKeepsSession(t *testing.T) {
	env := newSessionEnv(t)
	name := env.tenantA + "-ci"
	id := env.createTeamUser(t, env.tenantA, name)
	token := env.loginToken(t, "team_users", utils.PrincipalTeam, id)

	env.callAs(t, env.tenantA, team.UpdateTeamUser, map[string]any{"id": id.Hex(), "username": name, "permissions": map[string]any{}})

	code, _ := env.probe(t, token)
	assert.Equal(t, http.StatusOK, code)
}

func TestSession_AdminPasswordChangeRevokes(t *testing.T) {
	env := newSessionEnv(t)
	token := env.loginToken(t, "admins", utils.PrincipalAdmin, env.tenantAAdminID)

	env.callAs(t, env.tenantA, update.UpdateAdmin, map[string]any{"id": env.tenantAAdminID.Hex(), "username": env.tenantA, "password": "new"})

	code, _ := env.probe(t, token)
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestSession_TokenTypeMustMatchCollection(t *testing.T) {
	env := newSessionEnv(t)
	token, err := utils.GenerateSessionJWT(env.tenantAAdminID, utils.PrincipalTeam, 0, env.tenantA)
	require.NoError(t, err)

	code, _ := env.probe(t, token)
	assert.Equal(t, http.StatusUnauthorized, code)
}
