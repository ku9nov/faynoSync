package mongod

import (
	"context"

	"github.com/hashicorp/go-version"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (c *appRepository) RequiredIntermediateStep(ctx context.Context, owner, appName, channel, platform, arch, currentVersion, latestVersion string) (string, error) {
	// CheckRequiredMigrationStep parses versions with version.Must
	if _, err := version.NewVersion(currentVersion); err != nil {
		return "", nil
	}
	if _, err := version.NewVersion(latestVersion); err != nil {
		return "", nil
	}

	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	var appMetaLocal, channelMetaLocal, platformMetaLocal, archMetaLocal struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	if err := c.getMeta(ctx, metaCollection, "app_name", appName, &appMetaLocal, owner); err != nil {
		return "", err
	}
	if err := c.getMeta(ctx, metaCollection, "channel_name", channel, &channelMetaLocal, owner); err != nil {
		return "", err
	}
	if err := c.getMeta(ctx, metaCollection, "platform_name", platform, &platformMetaLocal, owner); err != nil {
		return "", err
	}
	if err := c.getMeta(ctx, metaCollection, "arch_id", arch, &archMetaLocal, owner); err != nil {
		return "", err
	}

	return c.CheckRequiredMigrationStep(ctx, collection, appMetaLocal.ID, currentVersion, latestVersion, channelMetaLocal.ID, platformMetaLocal.ID, archMetaLocal.ID)
}
