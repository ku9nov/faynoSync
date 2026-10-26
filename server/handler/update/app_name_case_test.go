package update

import (
	"context"
	"strings"
	"testing"

	"faynoSync/server/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Apps "MyApp" and "myapp" of one admin would share ONLINE_KEY_DIR/<admin>/<app>/ on a
// case-insensitive filesystem. Other admins' apps must not collide.
// To verify: In CreateApp/UpdateApp drop ensureAppNameFree; test will fail (no error).
func TestAppName_CaseVariantWithinOwner_Rejected(t *testing.T) {
	repository, db := testRepository(t)
	suffix := primitive.NewObjectID().Hex()[16:]
	owner, other := "appcaseowner"+suffix, "appcaseother"+suffix
	ctx := utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalAdmin, Username: owner})
	otherCtx := utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalAdmin, Username: other})
	t.Cleanup(func() {
		_, _ = db.Collection("apps_meta").DeleteMany(context.Background(), bson.M{"owner": bson.M{"$in": []string{owner, other}}})
	})
	name := "CaseApp" + suffix

	created, err := repository.CreateApp(name, "", "", false, "", false, false, false, owner, ctx)
	require.NoError(t, err)
	_, err = repository.CreateApp(strings.ToLower(name), "", "", false, "", false, false, false, owner, ctx)
	assert.EqualError(t, err, "app with this name already exists")

	_, err = repository.CreateApp(strings.ToLower(name), "", "", false, "", false, false, false, other, otherCtx)
	require.NoError(t, err, "another admin's app must not block the name")

	second, err := repository.CreateApp("Second"+suffix, "", "", false, "", false, false, false, owner, ctx)
	require.NoError(t, err)
	_, err = repository.UpdateApp(second.(primitive.ObjectID), strings.ToUpper(name), "", false, "", false, false, "", owner, ctx)
	assert.EqualError(t, err, "app with this name already exists")

	_, err = repository.UpdateApp(created.(primitive.ObjectID), strings.ToLower(name), "", false, "", false, false, "", owner, ctx)
	assert.NoError(t, err, "renaming an app to its own case variant must stay allowed")
}
