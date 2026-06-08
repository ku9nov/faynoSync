package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ReportApplication struct {
	Name    string `bson:"name" json:"name"`
	Version string `bson:"version" json:"version"`
	Channel string `bson:"channel" json:"channel"`
}

type ReportSystem struct {
	Platform string `bson:"platform" json:"platform"`
	Arch     string `bson:"arch" json:"arch"`
}

type ReportEvent struct {
	Type   string `bson:"type" json:"type"`
	Reason string `bson:"reason" json:"reason"`
}

type ReportDetails struct {
	Encoding    string `json:"encoding"`
	ContentType string `json:"content_type"`
	Payload     string `json:"payload"`
}

type ReportIngestRequest struct {
	Application ReportApplication `json:"application"`
	System      ReportSystem      `json:"system"`
	Event       ReportEvent       `json:"event"`
	Details     *ReportDetails    `json:"details,omitempty"`
}

type ReportIngestResponse struct {
	Status        string `json:"status"`
	GroupHash     string `json:"group_hash"`
	StoredDetails bool   `json:"stored_details"`
}

type ReportGroupStats struct {
	Count           int64              `bson:"count"`
	FirstSeen       primitive.DateTime `bson:"firstSeen"`
	LastSeen        primitive.DateTime `bson:"lastSeen"`
	DetailsStored   int64              `bson:"detailsStored"`
	DetailsRejected int64              `bson:"detailsRejected"`
}

type ReportGroup struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	GroupHash   string             `bson:"groupHash"`
	Application ReportApplication  `bson:"application"`
	System      ReportSystem       `bson:"system"`
	Event       ReportEvent        `bson:"event"`
	Stats       ReportGroupStats   `bson:"stats"`
	CreatedAt   primitive.DateTime `bson:"createdAt"`
	UpdatedAt   primitive.DateTime `bson:"updatedAt"`
}

type ReportBlobStorage struct {
	Driver           string `bson:"driver"`
	Bucket           string `bson:"bucket"`
	Key              string `bson:"key"`
	CompressedSize   int64  `bson:"compressedSize"`
	DecompressedSize int64  `bson:"decompressedSize"`
	ContentType      string `bson:"contentType"`
	Encoding         string `bson:"encoding"`
}

type ReportBlob struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	GroupHash   string             `bson:"groupHash"`
	Application ReportApplication  `bson:"application"`
	System      ReportSystem       `bson:"system"`
	Event       ReportEvent        `bson:"event"`
	Storage     ReportBlobStorage  `bson:"storage"`
	CreatedAt   primitive.DateTime `bson:"createdAt"`
	ExpiresAt   primitive.DateTime `bson:"expiresAt"`
}
