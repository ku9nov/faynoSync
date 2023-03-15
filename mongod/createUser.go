package mongod

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(client *mongo.Client, dbName string, flags map[string]interface{}) error {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(flags["user_password"].(string)), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	collection := client.Database(dbName).Collection("admins")
	user := bson.M{"username": flags["user_name"].(string), "password": string(hashedPassword)}

	_, err = collection.InsertOne(context.Background(), user)
	if err != nil {
		return err
	}

	return nil
}
