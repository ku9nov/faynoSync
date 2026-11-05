package team

import (
	"context"
	"net/http"
	"testing"

	"faynoSync/server/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Stored grant: apps.upload on app1.
func seedUploader(t *testing.T, db *mongo.Database, admin string) (id primitive.ObjectID, username string) {
	t.Helper()
	id, username = primitive.NewObjectID(), admin+"-uploader"
	_, err := db.Collection("team_users").InsertOne(context.Background(), bson.M{
		"_id": id, "username": username, "owner": admin,
		"permissions": bson.M{"apps": bson.M{"upload": true, "allowed": []string{"app1"}}},
	})
	require.NoError(t, err)
	return id, username
}

func storedPermissions(t *testing.T, db *mongo.Database, id primitive.ObjectID) model.Permissions {
	t.Helper()
	var user model.TeamUser
	require.NoError(t, db.Collection("team_users").FindOne(context.Background(), bson.M{"_id": id}).Decode(&user))
	return user.Permissions
}

func revokeAllPermissions() map[string]any {
	return map[string]any{
		"apps":      map[string]any{"create": false, "delete": false, "edit": false, "download": false, "upload": false, "allowed": []string{}},
		"channels":  map[string]any{"allowed": []string{}},
		"platforms": map[string]any{"allowed": []string{}},
		"archs":     map[string]any{"allowed": []string{}},
	}
}

// Revoking every permission is an explicit change and must reach the database.
// To verify: In UpdateTeamUser write permissions only when some flag is true; test will fail (old grant kept).
func TestUpdateTeamUser_RevokeAllPermissions_Persisted(t *testing.T) {
	db := identityTestDB(t)
	admin, _ := identityNames(t, db)
	id, username := seedUploader(t, db, admin)

	w := callAsAdmin(t, admin, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": id.Hex(), "username": username, "permissions": revokeAllPermissions()})

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	perms := storedPermissions(t, db, id)
	assert.False(t, perms.Apps.Upload, "apps.upload must be revoked")
	assert.Empty(t, perms.Apps.Allowed, "allowed apps must be cleared")
}

// Control: a partial change with one flag left true is persisted.
func TestUpdateTeamUser_PartialRevoke_Persisted(t *testing.T) {
	db := identityTestDB(t)
	admin, _ := identityNames(t, db)
	id, username := seedUploader(t, db, admin)
	perms := revokeAllPermissions()
	perms["apps"].(map[string]any)["download"] = true

	w := callAsAdmin(t, admin, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": id.Hex(), "username": username, "permissions": perms})

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	stored := storedPermissions(t, db, id)
	assert.False(t, stored.Apps.Upload)
	assert.True(t, stored.Apps.Download)
}

// Omitting permissions (rename only) must keep the stored grant.
func TestUpdateTeamUser_PermissionsOmitted_NotTouched(t *testing.T) {
	db := identityTestDB(t)
	admin, _ := identityNames(t, db)
	id, username := seedUploader(t, db, admin)

	w := callAsAdmin(t, admin, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": id.Hex(), "username": username + "2"})

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	stored := storedPermissions(t, db, id)
	assert.True(t, stored.Apps.Upload)
	assert.Equal(t, []string{"app1"}, stored.Apps.Allowed)
}
