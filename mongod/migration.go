package mongod

import (
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mongodb"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

func RunMigrations(client *mongo.Client, dbName string, flags map[string]interface{}) {
	// Create a new MongoDB migration instance
	sourceDriver, err := (&file.File{}).Open("mongod/migrations/")
	if err != nil {
		panic(err)
	}
	dbDriver, err := mongodb.WithInstance(client, &mongodb.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithInstance("file", sourceDriver, dbName, dbDriver)
	if err != nil {
		panic(err)
	}
	applied := false
	if err := m.Up(); err != nil {
		version, _, _ := m.Version()
		if version > 0 {
			applied = true
		}
	}

	if flags["rollback"].(bool) {
		if err := m.Down(); err != nil {
			panic(err)
		}
		logrus.Infoln("Migrations rollback completed")
		return
	}
	if !applied {
		logrus.Infoln("Migrations completed")
	} else {
		logrus.Infoln("Migrations not applied")
	}
}
