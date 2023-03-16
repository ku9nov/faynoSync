package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type App struct {
	ID         primitive.ObjectID `bson:"_id"`
	AppName    string             `bson:"app_name"`
	Version    string             `bson:"version"`
	Link       string             `bson:"link"`
	Updated_at primitive.DateTime `bson:"updated_at"`
}
