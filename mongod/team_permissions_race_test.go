package mongod

import (
	"context"
	"os"
	"testing"

	"faynoSync/server/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// A team user's create reads its permissions at request start and grants itself the new
// resource at the end. An admin revocation landing in between must survive that write.
// To verify: In updateTeamUserPermissions $set the whole permissions object from the snapshot; test will fail (grants restored).
func TestUpdateTeamUserPermissions_StaleSnapshotKeepsRevocation(t *testing.T) {
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	repo := NewAppRepository(&configDB, client).(*appRepository)
	users := client.Database(configDB.Database).Collection("team_users")
	ctx := context.Background()

	var snapshot model.TeamUser
	snapshot.ID = primitive.NewObjectID()
	snapshot.Username = "racer" + snapshot.ID.Hex()[16:]
	snapshot.Owner = "raceowner" + snapshot.ID.Hex()[16:]
	snapshot.Permissions.Channels.Create = true
	snapshot.Permissions.Channels.Allowed = []string{"old-channel"}
	snapshot.Permissions.Apps.Edit = true
	_, err := users.InsertOne(ctx, snapshot)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = users.DeleteOne(context.Background(), bson.M{"_id": snapshot.ID}) })

	// Admin revokes everything after the snapshot was read.
	_, err = users.UpdateOne(ctx, bson.M{"_id": snapshot.ID}, bson.M{"$set": bson.M{"permissions": model.Permissions{}}})
	require.NoError(t, err)

	newChannel := primitive.NewObjectID()
	require.NoError(t, repo.updateTeamUserPermissions(snapshot, newChannel, "channel", ctx))

	var stored model.TeamUser
	require.NoError(t, users.FindOne(ctx, bson.M{"_id": snapshot.ID}).Decode(&stored))
	assert.False(t, stored.Permissions.Channels.Create, "revoked channels.create must stay revoked")
	assert.False(t, stored.Permissions.Apps.Edit, "revoked apps.edit must stay revoked")
	assert.NotContains(t, stored.Permissions.Channels.Allowed, "old-channel", "revoked allowed entries must stay removed")
	assert.Contains(t, stored.Permissions.Channels.Allowed, newChannel.Hex(), "the created channel is still granted")
}
