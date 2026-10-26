package team

import (
	"bytes"
	"context"
	"encoding/json"
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
	"go.mongodb.org/mongo-driver/mongo"
)

func identityTestDB(t *testing.T) *mongo.Database {
	t.Helper()
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client.Database(configDB.Database)
}

func callAsAdmin(t *testing.T, admin string, handler func(*gin.Context), body any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", admin)
	handler(c)
	return w
}

func teamUserID(t *testing.T, db *mongo.Database, username, owner string) string {
	t.Helper()
	var doc struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	require.NoError(t, db.Collection("team_users").FindOne(context.Background(), bson.M{"username": username, "owner": owner}).Decode(&doc))
	return doc.ID.Hex()
}

func identityNames(t *testing.T, db *mongo.Database) (attacker, victim string) {
	t.Helper()
	ctx := context.Background()
	suffix := primitive.NewObjectID().Hex()[16:]
	attacker, victim = "idattacker"+suffix, "idvictim"+suffix
	_, err := db.Collection("admins").InsertMany(ctx, []any{bson.M{"username": attacker}, bson.M{"username": victim}})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": bson.M{"$in": []string{attacker, victim}}})
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": bson.M{"$in": []string{attacker, victim}}})
	})
	return attacker, victim
}

// Whatever the fix (reject the name, or resolve admins first), an admin's
// username must keep resolving to that admin's own tenant.
func assertAdminStillOwnsItself(t *testing.T, db *mongo.Database, w *httptest.ResponseRecorder, victim string) {
	t.Helper()
	if w.Code != http.StatusOK {
		return
	}
	owner, err := utils.ResolveRequestOwner(context.Background(), victim, db)
	require.NoError(t, err)
	assert.Equal(t, victim, owner, "admin %q now resolves to another tenant", victim)
}

// To verify: In CreateTeamUser check the username only against team_users; test will fail (victim admin resolves to attacker).
func TestCreateTeamUser_UsernameOfAnotherAdmin_DoesNotHijackOwner(t *testing.T) {
	db := identityTestDB(t)
	attacker, victim := identityNames(t, db)

	w := callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": victim, "password": "p", "permissions": map[string]any{}})

	assertAdminStillOwnsItself(t, db, w, victim)
}

// To verify: In UpdateTeamUser write the new username without a uniqueness check; test will fail (victim admin resolves to attacker).
func TestUpdateTeamUser_RenameToAnotherAdmin_DoesNotHijackOwner(t *testing.T) {
	db := identityTestDB(t)
	attacker, victim := identityNames(t, db)
	w := callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": attacker + "-ci", "password": "p", "permissions": map[string]any{}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = callAsAdmin(t, attacker, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": teamUserID(t, db, attacker+"-ci", attacker), "username": victim})

	assertAdminStillOwnsItself(t, db, w, victim)
}

// sessionAs runs the authenticated chain a normal route uses and reports the
// tenant the request is executed in.
func sessionAs(t *testing.T, db *mongo.Database, token string) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/probe",
		utils.AuthMiddleware(db),
		utils.CheckPermission(utils.PermissionDownload, utils.ResourceApps, db),
		utils.ResolveOwnerMiddleware(db),
		func(c *gin.Context) {
			owner, _ := utils.GetOwnerFromContext(c)
			c.JSON(http.StatusOK, gin.H{"owner": owner})
		},
	)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	var body struct {
		Owner string `json:"owner"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Owner
}

func freedNameTokenReuse(t *testing.T, free func(db *mongo.Database, tenantA, name string)) {
	db := identityTestDB(t)
	tenantA, tenantD := identityNames(t, db)
	oldSecret := viper.GetViper().GetString("JWT_SECRET")
	viper.GetViper().Set("JWT_SECRET", "identity-test-secret")
	t.Cleanup(func() { viper.GetViper().Set("JWT_SECRET", oldSecret) })

	name := tenantA + "-deploy"
	w := callAsAdmin(t, tenantA, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": name, "password": "p", "permissions": map[string]any{}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var holder struct {
		ID           primitive.ObjectID `bson:"_id"`
		TokenVersion int64              `bson:"token_version"`
	}
	require.NoError(t, db.Collection("team_users").FindOne(context.Background(), bson.M{"username": name, "owner": tenantA}).Decode(&holder))
	token, err := utils.GenerateSessionJWT(holder.ID, utils.PrincipalTeam, holder.TokenVersion, name)
	require.NoError(t, err)
	code, owner := sessionAs(t, db, token)
	require.Equal(t, http.StatusForbidden, code, "the session must authenticate before the name is freed (403: no download permission)")

	free(db, tenantA, name)

	w = callAsAdmin(t, tenantD, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": name, "password": "p2", "permissions": map[string]any{"apps": map[string]any{"download": true}}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	code, owner = sessionAs(t, db, token)
	assert.Equal(t, http.StatusUnauthorized, code, "token issued to tenant %s's team user must not act as tenant %s's new one (served owner %q)", tenantA, tenantD, owner)
}

// To verify: In AuthMiddleware accept any validly signed token without a principal/version check; test will fail (200 in tenant D).
func TestAuth_TokenOfDeletedTeamUser_NotReusableByNextHolder(t *testing.T) {
	freedNameTokenReuse(t, func(db *mongo.Database, tenantA, name string) {
		w := callAsAdmin(t, tenantA, func(c *gin.Context) { DeleteTeamUser(c, db) }, map[string]any{"id": teamUserID(t, db, name, tenantA)})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}

// To verify: In AuthMiddleware accept any validly signed token without a principal/version check; test will fail (200 in tenant D).
func TestAuth_TokenOfRenamedTeamUser_NotReusableByNextHolder(t *testing.T) {
	freedNameTokenReuse(t, func(db *mongo.Database, tenantA, name string) {
		w := callAsAdmin(t, tenantA, func(c *gin.Context) { UpdateTeamUser(c, db) },
			map[string]any{"id": teamUserID(t, db, name, tenantA), "username": name + "-old"})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}
