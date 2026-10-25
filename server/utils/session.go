package utils

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	PrincipalAdmin = "admin"
	PrincipalTeam  = "team"
)

var (
	errSessionClaims  = errors.New("token has no session claims, log in again")
	errSessionRevoked = errors.New("session is no longer valid, log in again")
)

// SessionClaims bind a JWT to one principal document, not to the username it
// had at login: names can be freed and reused by another tenant.
type SessionClaims struct {
	Subject  primitive.ObjectID
	Type     string
	Version  int64
	Username string
}

func GenerateSessionJWT(subject primitive.ObjectID, principalType string, version int64, username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"sub":      subject.Hex(),
		"typ":      principalType,
		"ver":      version,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(viper.GetViper().GetString("JWT_SECRET")))
}

func ParseSessionJWT(tokenString string) (SessionClaims, error) {
	token, err := ValidateJWT(tokenString)
	if err != nil {
		return SessionClaims{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return SessionClaims{}, errInvalidClaims
	}
	username, okUsername := claims["username"].(string)
	sub, okSub := claims["sub"].(string)
	principalType, okType := claims["typ"].(string)
	version, okVersion := claims["ver"].(float64)
	if !okUsername || !okSub || !okType || !okVersion {
		return SessionClaims{}, errSessionClaims
	}
	subject, err := primitive.ObjectIDFromHex(sub)
	if err != nil || (principalType != PrincipalAdmin && principalType != PrincipalTeam) || version != float64(int64(version)) {
		return SessionClaims{}, errSessionClaims
	}
	return SessionClaims{Subject: subject, Type: principalType, Version: int64(version), Username: username}, nil
}

// VerifySession returns the username the principal currently has. It fails
// with errSessionRevoked when the principal is gone or its token_version moved
// on (rename, password change).
func VerifySession(ctx context.Context, database *mongo.Database, claims SessionClaims) (string, error) {
	collection := "admins"
	if claims.Type == PrincipalTeam {
		collection = "team_users"
	}
	var principal struct {
		Username     string `bson:"username"`
		TokenVersion int64  `bson:"token_version"`
	}
	err := database.Collection(collection).FindOne(ctx,
		bson.M{"_id": claims.Subject},
		options.FindOne().SetProjection(bson.M{"username": 1, "token_version": 1}),
	).Decode(&principal)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", errSessionRevoked
	}
	if err != nil {
		return "", err
	}
	if principal.TokenVersion != claims.Version || principal.Username != claims.Username {
		return "", errSessionRevoked
	}
	return principal.Username, nil
}

func SessionUsernameFromJWT(ctx context.Context, database *mongo.Database, tokenString string) (string, error) {
	claims, err := ParseSessionJWT(tokenString)
	if err != nil {
		return "", err
	}
	return VerifySession(ctx, database, claims)
}
