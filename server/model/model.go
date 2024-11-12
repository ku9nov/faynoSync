package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type Artifact struct {
	Link     string             `bson:"link"`
	Platform primitive.ObjectID `bson:"platform"`
	Arch     primitive.ObjectID `bson:"arch"`
	Package  string             `bson:"package"`
}

type App struct {
	ID         primitive.ObjectID `bson:"_id"`
	AppName    string             `bson:"app_name"`
	Logo       string             `bson:"logo"`
	Updated_at primitive.DateTime `bson:"updated_at"`
}

type SpecificApp struct {
	ID         primitive.ObjectID `bson:"_id"`
	AppID      primitive.ObjectID `bson:"app_id"`
	AppName    string             `bson:"app_name,omitempty" json:"AppName,omitempty"`
	Version    string             `bson:"version"`
	ChannelID  primitive.ObjectID `bson:"channel_id"`
	Channel    string             `bson:"channel,omitempty" json:"channel,omitempty"`
	Published  bool               `bson:"published"`
	Critical   bool               `bson:"critical"`
	Artifacts  []Artifact         `bson:"artifacts"`
	Changelog  []Changelog        `bson:"changelog"`
	Updated_at primitive.DateTime `bson:"updated_at"`
}

type SpecificArtifactsWithoutIDs struct {
	Link     string `bson:"link" json:"link"`
	Platform string `bson:"platform" json:"platform"`
	Arch     string `bson:"arch" json:"arch"`
	Package  string `bson:"package" json:"package"`
}

type SpecificAppWithoutIDs struct {
	ID        primitive.ObjectID            `bson:"_id,omitempty" json:"ID"`
	AppName   string                        `bson:"app_name" json:"AppName"`
	Version   string                        `bson:"version" json:"Version"`
	Channel   string                        `bson:"channel" json:"Channel"`
	Published bool                          `bson:"published" json:"Published"`
	Critical  bool                          `bson:"critical" json:"Critical"`
	Artifacts []SpecificArtifactsWithoutIDs `bson:"artifacts" json:"Artifacts"`
	Changelog []Changelog                   `bson:"changelog" json:"Changelog"`
	UpdatedAt primitive.DateTime            `bson:"updated_at" json:"Updated_at"`
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
