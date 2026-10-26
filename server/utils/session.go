package utils

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"time"

	"github.com/gin-gonic/gin"
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
	principal, err := VerifySessionPrincipal(ctx, database, claims)
	if err != nil {
		return "", err
	}
	return principal.Username, nil
}

func VerifySessionPrincipal(ctx context.Context, database *mongo.Database, claims SessionClaims) (Principal, error) {
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
		return Principal{}, errSessionRevoked
	}
	if err != nil {
		return Principal{}, err
	}
	if principal.TokenVersion != claims.Version || principal.Username != claims.Username {
		return Principal{}, errSessionRevoked
	}
	return Principal{Type: claims.Type, ID: claims.Subject, Username: principal.Username}, nil
}

// SessionPrincipalContext attaches the principal of an already verified session token to ctx.
func SessionPrincipalContext(ctx context.Context, tokenString, username string) context.Context {
	claims, err := ParseSessionJWT(tokenString)
	if err != nil || claims.Username != username {
		return ctx
	}
	return WithPrincipal(ctx, Principal{Type: claims.Type, ID: claims.Subject, Username: username})
}

func SessionUsernameFromJWT(ctx context.Context, database *mongo.Database, tokenString string) (string, error) {
	claims, err := ParseSessionJWT(tokenString)
	if err != nil {
		return "", err
	}
	return VerifySession(ctx, database, claims)
}

// Principal is the authenticated caller. Authorization must branch on Type and
// ID, never on Username: an admin and a team user can share a name.
type Principal struct {
	Type     string
	ID       primitive.ObjectID
	Username string
}

type principalContextKey struct{}

const principalGinKey = "principal"

var errNoPrincipal = errors.New("no authenticated principal")

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || (principal.Type != PrincipalAdmin && principal.Type != PrincipalTeam) {
		return Principal{}, false
	}
	return principal, true
}

func setPrincipal(c *gin.Context, principal Principal) {
	c.Set(principalGinKey, principal)
	c.Request = c.Request.WithContext(WithPrincipal(c.Request.Context(), principal))
}

// CallerTeamUser returns the caller's team user document, or nil for an admin.
// A team principal is resolved by _id only.
func CallerTeamUser(ctx context.Context, database *mongo.Database) (*model.TeamUser, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return nil, errNoPrincipal
	}
	if principal.Type == PrincipalAdmin {
		return nil, nil
	}
	var teamUser model.TeamUser
	err := database.Collection("team_users").FindOne(ctx, bson.M{"_id": principal.ID}).Decode(&teamUser)
	if errors.Is(err, mongo.ErrNoDocuments) {
		// Never surface ErrNoDocuments: callers read it as "not a team user", i.e. an admin.
		return nil, errSessionRevoked
	}
	if err != nil {
		return nil, err
	}
	return &teamUser, nil
}
