package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type Artifact struct {
	Link     string `bson:"link"`
	Platform string `bson:"platform"`
	Arch     string `bson:"arch"`
	Package  string `bson:"package"`
}

type App struct {
	ID         primitive.ObjectID `bson:"_id"`
	AppName    string             `bson:"app_name"`
	Version    string             `bson:"version"`
	Channel    string             `bson:"channel"`
	Published  bool               `bson:"published"`
	Artifacts  []Artifact         `bson:"artifacts"`
	Updated_at primitive.DateTime `bson:"updated_at"`
}

type Channel struct {
	ID          primitive.ObjectID `bson:"_id"`
	ChannelName string             `bson:"channel_name"`
	Updated_at  primitive.DateTime `bson:"updated_at"`
}

type Platform struct {
	ID           primitive.ObjectID `bson:"_id"`
	PlatformName string             `bson:"platform_name"`
	Updated_at   primitive.DateTime `bson:"updated_at"`
}

type Arch struct {
	ID         primitive.ObjectID `bson:"_id"`
	ArchID     string             `bson:"arch_id"`
	Updated_at primitive.DateTime `bson:"updated_at"`
}
