package mongod

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

func ConnectToDatabase(mongoUrl string, flags map[string]interface{}) (*mongo.Client, connstring.ConnString) {
	uriOptions, err := connstring.Parse(mongoUrl)
	if err != nil {
		panic(err)
	}
	// set up the connection options
	clientOptions := options.Client().ApplyURI(mongoUrl)

	// connect to the MongoDB server
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// check if we were able to connect to the server
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")
	if flags["migration"].(bool) {
		RunMigrations(client, uriOptions.Database, flags)
	}
	return client, uriOptions
}
