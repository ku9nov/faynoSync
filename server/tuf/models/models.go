package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// BootstrapPayload represents the bootstrap payload structure
type BootstrapPayload struct {
	Settings Settings                `json:"settings"`
	Metadata map[string]RootMetadata `json:"metadata"`
	Timeout  *int                    `json:"timeout,omitempty"`
}

type Settings struct {
	Roles RolesData `json:"roles"`
}

type RolesData struct {
	Root      RoleExpiration `json:"root"`
	Timestamp RoleExpiration `json:"timestamp"`
	Snapshot  RoleExpiration `json:"snapshot"`
	Targets   RoleExpiration `json:"targets"`
	Bins      *BinsRole      `json:"bins,omitempty"`
}

type RoleExpiration struct {
	Expiration int `json:"expiration"`
}

type BinsRole struct {
	Expiration            int `json:"expiration"`
	NumberOfDelegatedBins int `json:"number_of_delegated_bins"`
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
	RoleName   string             `bson:"role_name" json:"role_name"` // "root", "targets", "snapshot", "timestamp"
	KeyID      string             `bson:"key_id" json:"key_id"`       // Public key ID
	PrivateKey string             `bson:"private_key" json:"-"`       // Base64 encoded private key (not returned in JSON)
	KeyType    string             `bson:"key_type" json:"key_type"`   // "ed25519", "rsa", "ecdsa"
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at" json:"updated_at"`
}
