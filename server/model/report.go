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

type PaginatedReportGroups struct {
	Items []*ReportGroup `json:"items"`
	Total int64          `json:"total"`
	Page  int64          `json:"page"`
	Limit int64          `json:"limit"`
}

type ReportContext struct {
	AppID          primitive.ObjectID `bson:"app_id"`
	Owner          string             `bson:"owner"`
	AppName        string             `bson:"app_name"`
	ReportsEnabled bool               `bson:"reports"`
}

type ReportGroupStats struct {
	Count           int64              `bson:"count" json:"count"`
	FirstSeen       primitive.DateTime `bson:"firstSeen" json:"first_seen"`
	LastSeen        primitive.DateTime `bson:"lastSeen" json:"last_seen"`
	DetailsStored   int64              `bson:"detailsStored" json:"details_stored"`
	DetailsRejected int64              `bson:"detailsRejected" json:"details_rejected"`
}

type ReportGroup struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	GroupHash   string             `bson:"groupHash" json:"group_hash"`
	AppID       primitive.ObjectID `bson:"app_id" json:"app_id"`
	Owner       string             `bson:"owner" json:"-"`
	Application ReportApplication  `bson:"application" json:"application"`
	System      ReportSystem       `bson:"system" json:"system"`
	Event       ReportEvent        `bson:"event" json:"event"`
	Stats       ReportGroupStats   `bson:"stats" json:"stats"`
	CreatedAt   primitive.DateTime `bson:"createdAt" json:"created_at"`
	UpdatedAt   primitive.DateTime `bson:"updatedAt" json:"updated_at"`
}

type ReportBlobStorage struct {
	Driver           string `bson:"driver" json:"driver"`
	Bucket           string `bson:"bucket" json:"-"`
	Key              string `bson:"key" json:"key"`
	CompressedSize   int64  `bson:"compressedSize" json:"compressed_size"`
	DecompressedSize int64  `bson:"decompressedSize" json:"decompressed_size"`
	ContentType      string `bson:"contentType" json:"content_type"`
	Encoding         string `bson:"encoding" json:"encoding"`
}

type ReportBlob struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	GroupHash   string             `bson:"groupHash" json:"group_hash"`
	AppID       primitive.ObjectID `bson:"app_id" json:"app_id"`
	Owner       string             `bson:"owner" json:"-"`
	Application ReportApplication  `bson:"application" json:"application"`
	System      ReportSystem       `bson:"system" json:"system"`
	Event       ReportEvent        `bson:"event" json:"event"`
	Storage     ReportBlobStorage  `bson:"storage" json:"storage"`
	CreatedAt   primitive.DateTime `bson:"createdAt" json:"created_at"`
	ExpiresAt   primitive.DateTime `bson:"expiresAt" json:"expires_at"`
}
