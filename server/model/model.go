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
	Critical   bool               `bson:"critical"`
	Artifacts  []Artifact         `bson:"artifacts"`
	Changelog  []Changelog        `bson:"changelog"`
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

type Changelog struct {
	Version string `bson:"version"`
	Changes string `bson:"changes"`
	Date    string `bson:"date"`
}

type Credentials struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	SecretKey string `json:"api_key"`
}

type UpRequest struct {
	Id        string `json:"id"`
	AppName   string `json:"app_name"`
	Version   string `json:"version"`
	Channel   string `json:"channel"`
	Publish   bool   `json:"publish"`
	Critical  bool   `json:"critical"`
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	Changelog string `json:"changelog"`
}
