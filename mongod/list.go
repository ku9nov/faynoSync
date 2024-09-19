package mongod

import (
	"context"
	"faynoSync/server/model"
	"reflect"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (c *appRepository) listItems(ctx context.Context, collectionName string, filter bson.M, resultSlice interface{}) error {
	findOptions := options.Find()
	findOptions.SetLimit(100)

	collection := c.client.Database(c.config.Database).Collection(collectionName)

	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		logrus.Fatal(err)
		return err
	}
	defer cur.Close(ctx)

	// Use reflection to access the result slice
	sliceValue := reflect.ValueOf(resultSlice).Elem()
	itemType := sliceValue.Type().Elem()

	for cur.Next(ctx) {
		item := reflect.New(itemType).Interface()
		if err := cur.Decode(item); err != nil {
			logrus.Fatal(err)
			return err
		}

		sliceValue.Set(reflect.Append(sliceValue, reflect.ValueOf(item).Elem()))
	}

	if err := cur.Err(); err != nil {
		logrus.Fatal(err)
		return err
	}

	return nil
}

func (c *appRepository) ListChannels(ctx context.Context) ([]*model.Channel, error) {
	var channels []*model.Channel
	filter := bson.M{"channel_name": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, &channels); err != nil {
		return nil, err
	}
	return channels, nil
}

func (c *appRepository) ListPlatforms(ctx context.Context) ([]*model.Platform, error) {
	var platforms []*model.Platform
	filter := bson.M{"platform_name": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, &platforms); err != nil {
		return nil, err
	}
	return platforms, nil
}

func (c *appRepository) ListArchs(ctx context.Context) ([]*model.Arch, error) {
	var archs []*model.Arch
	filter := bson.M{"arch_id": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, &archs); err != nil {
		return nil, err
	}
	return archs, nil
}

func (c *appRepository) ListApps(ctx context.Context) ([]*model.App, error) {
	var apps []*model.App
	filter := bson.M{"app_name": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}
