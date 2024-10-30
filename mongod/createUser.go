package mongod

import (
	"context"
	"faynoSync/server/model"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(client *mongo.Client, dbName *mongo.Database, credentials *model.Credentials) error {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
	if err != nil {
		logrus.Fatal(err)
	}
	collection := dbName.Collection("admins")
	filter := bson.D{
		{Key: "username", Value: credentials.Username},
		{Key: "password", Value: string(hashedPassword)},
		{Key: "updated_at", Value: time.Now()},
	}

	_, err = collection.InsertOne(context.Background(), filter)
	if err != nil {
		return err
	}

	return nil
}
