package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// BootstrapPayload represents the bootstrap payload structure
type BootstrapPayload struct {
	AppName  string                  `json:"appName" binding:"required"`
	Settings Settings                `json:"settings"`
	Metadata map[string]RootMetadata `json:"metadata"`
	Timeout  *int                    `json:"timeout,omitempty"`
}

type Settings struct {
	Roles RolesData `json:"roles"`
}

type RolesData struct {
	Root        RoleExpiration  `json:"root"`
	Timestamp   RoleExpiration  `json:"timestamp"`
	Snapshot    RoleExpiration  `json:"snapshot"`
	Targets     RoleExpiration  `json:"targets"`
	Delegations *TUFDelegations `json:"delegations,omitempty"`
}

type RoleExpiration struct {
	Expiration int `json:"expiration"`
}

type RootMetadata struct {
	Signatures []Signature `json:"signatures"`
	Signed     Signed      `json:"signed"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Signed struct {
	Type               string          `json:"_type"`
	Version            int             `json:"version"`
	SpecVersion        string          `json:"spec_version"`
	Expires            string          `json:"expires"`
	ConsistentSnapshot bool            `json:"consistent_snapshot"`
	Keys               map[string]Key  `json:"keys"`
	Roles              map[string]Role `json:"roles"`
}

type Key struct {
	KeyType string `json:"keytype"`
	Scheme  string `json:"scheme"`
	KeyVal  KeyVal `json:"keyval"`
}

type KeyVal struct {
	Public string `json:"public"`
}

type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

// TUFPrivateKey represents a private key stored in MongoDB
type TUFPrivateKey struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	AdminName  string             `bson:"admin_name" json:"admin_name"`
	AppName    string             `bson:"app_name,omitempty" json:"app_name,omitempty"` // Optional app name for app-specific keys
	RoleName   string             `bson:"role_name" json:"role_name"`                   // "root", "targets", "snapshot", "timestamp"
	KeyID      string             `bson:"key_id" json:"key_id"`                         // Public key ID
	PrivateKey string             `bson:"private_key" json:"-"`                         // Base64 encoded private key (not returned in JSON)
	KeyType    string             `bson:"key_type" json:"key_type"`                     // "ed25519", "rsa", "ecdsa"
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at" json:"updated_at"`
}

// TUFDelegations represents custom target delegations
type TUFDelegations struct {
	Keys  map[string]TUFKey  `json:"keys"`
	Roles []TUFDelegatedRole `json:"roles"`
}

// TUFKey represents a public key for delegations
type TUFKey struct {
	KeyType string    `json:"keytype"`
	Scheme  string    `json:"scheme"`
	KeyVal  TUFKeyVal `json:"keyval"`
}

// TUFKeyVal represents key value (public key)
type TUFKeyVal struct {
	Public string `json:"public"`
}

// TUFDelegatedRole represents a custom delegated role
type TUFDelegatedRole struct {
	Name        string   `json:"name"`
	Terminating bool     `json:"terminating"`
	KeyIDs      []string `json:"keyids"`
	Threshold   int      `json:"threshold"`
	Paths       []string `json:"paths"`
}

type GetConfigResponse struct {
	Data    map[string]interface{} `json:"data"`
	Message string                 `json:"message"`
}

type PutConfigPayload struct {
	Settings SettingsPayload `json:"settings" binding:"required"`
}

type SettingsPayload struct {
	Expiration map[string]int `json:"expiration" binding:"required"`
}

type PutConfigResponse struct {
	Data    PutConfigData `json:"data"`
	Message string        `json:"message"`
}

type PutConfigData struct {
	TaskID     string    `json:"task_id"`
	LastUpdate time.Time `json:"last_update"`
}

type MetadataSignPostPayload struct {
	Role      string    `json:"role" binding:"required"`
	Signature Signature `json:"signature" binding:"required"`
}

type MetadataSignPostResponse struct {
	Data    MetadataSignData `json:"data"`
	Message string           `json:"message"`
}

type MetadataSignData struct {
	TaskID     string    `json:"task_id"`
	LastUpdate time.Time `json:"last_update"`
}

type MetadataPostPayload struct {
	Metadata map[string]RootMetadata `json:"metadata" binding:"required"`
}

type MetadataPostResponse struct {
	Data    MetadataPostData `json:"data"`
	Message string           `json:"message"`
}

type MetadataPostData struct {
	TaskID     string    `json:"task_id"`
	LastUpdate time.Time `json:"last_update"`
}
