package mongod

import (
	"context"
	"errors"
	"faynoSync/server/utils"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mongodb"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

func newMigration(client *mongo.Client, dbName string) (*migrate.Migrate, error) {
	sourceDriver, err := (&file.File{}).Open("mongod/migrations/")
	if err != nil {
		return nil, err
	}
	dbDriver, err := mongodb.WithInstance(client, &mongodb.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithInstance("file", sourceDriver, dbName, dbDriver)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func RunMigrationsUp(client *mongo.Client, dbName string) error {
	m, err := newMigration(client, dbName)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return err
		}
		logrus.Infoln("No pending migrations to apply")
	} else {
		logrus.Infoln("Migrations completed")
	}
	return backfillPrivateDownloads(context.Background(), client.Database(dbName), utils.DefaultDownloadMode(viper.GetViper()))
}

func RunMigrationsDown(client *mongo.Client, dbName string) error {
	m, err := newMigration(client, dbName)
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			logrus.Infoln("No migrations to roll back")
			return nil
		}
		return err
	}
	logrus.Infoln("Migrations rollback completed")
	return nil
}
