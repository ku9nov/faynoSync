package download

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Embedding the interface makes any repository call the test did not stub panic.
type fakeRepository struct {
	db.AppRepository
	artifacts   map[string]*model.PrivateArtifact
	downloaders map[string]bool
	tokens      map[string]primitive.ObjectID
}

func (f *fakeRepository) FindPrivateArtifact(_ context.Context, key string) (*model.PrivateArtifact, error) {
	if artifact, ok := f.artifacts[key]; ok {
		return artifact, nil
	}
	return nil, db.ErrPrivateArtifactNotFound
}

func (f *fakeRepository) CanDownloadPrivateArtifact(_ context.Context, username string, _ *model.PrivateArtifact) (bool, error) {
	return f.downloaders[username], nil
}

func (f *fakeRepository) HasDownloadToken(_ context.Context, token string, artifact *model.PrivateArtifact) (bool, error) {
	channelID, ok := f.tokens[token]
	return ok && channelID == artifact.ChannelID, nil
}

func newTestContext(headers map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/download?key=k", nil)
	for name, value := range headers {
		c.Request.Header.Set(name, value)
	}
	return c, recorder
}

func TestAuthorizeDownload(t *testing.T) {
	viper.Set("JWT_SECRET", "test-secret")
	adminJWT, err := utils.GenerateJWT("admin")
	if err != nil {
		t.Fatal(err)
	}
	strangerJWT, err := utils.GenerateJWT("stranger")
	if err != nil {
		t.Fatal(err)
	}

	stable := primitive.NewObjectID()
	beta := primitive.NewObjectID()
	repo := &fakeRepository{
		downloaders: map[string]bool{"admin": true},
		tokens:      map[string]primitive.ObjectID{"fnd_stable": stable, "fnd_beta": beta},
	}
	strict := &model.PrivateArtifact{ChannelID: stable, DownloadMode: utils.DownloadModeStrict}
	unlisted := &model.PrivateArtifact{ChannelID: stable, DownloadMode: utils.DownloadModeUnlisted}
	unset := &model.PrivateArtifact{ChannelID: stable}

	cases := map[string]struct {
		artifact    *model.PrivateArtifact
		headers     map[string]string
		wantJSON    bool
		wantAllowed bool
	}{
		"strict anonymous":                 {strict, nil, false, false},
		"strict token of own channel":      {strict, map[string]string{utils.DownloadTokenHeader: "fnd_stable"}, false, true},
		"strict token of other channel":    {strict, map[string]string{utils.DownloadTokenHeader: "fnd_beta"}, false, false},
		"strict unknown token":             {strict, map[string]string{utils.DownloadTokenHeader: "fnd_nope"}, false, false},
		"strict api token as bearer":       {strict, map[string]string{"Authorization": "Bearer fns_abc"}, false, false},
		"strict jwt with access":           {strict, map[string]string{"Authorization": "Bearer " + adminJWT}, true, true},
		"strict jwt without access":        {strict, map[string]string{"Authorization": "Bearer " + strangerJWT}, false, false},
		"strict download token as bearer":  {strict, map[string]string{"Authorization": "Bearer fnd_stable"}, false, false},
		"unlisted anonymous":               {unlisted, nil, false, true},
		"unlisted jwt with access":         {unlisted, map[string]string{"Authorization": "Bearer " + adminJWT}, true, true},
		"unlisted jwt without access":      {unlisted, map[string]string{"Authorization": "Bearer " + strangerJWT}, false, true},
		"missing mode fails closed":        {unset, nil, false, false},
		"missing mode still accepts token": {unset, map[string]string{utils.DownloadTokenHeader: "fnd_stable"}, false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestContext(tc.headers)
			gotJSON, gotAllowed, err := authorizeDownload(context.Background(), c, repo, tc.artifact)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotJSON != tc.wantJSON || gotAllowed != tc.wantAllowed {
				t.Fatalf("got json=%v allowed=%v, want json=%v allowed=%v", gotJSON, gotAllowed, tc.wantJSON, tc.wantAllowed)
			}
		})
	}
}

func TestDeniedDownloadMatchesUnknownKey(t *testing.T) {
	repo := &fakeRepository{
		artifacts: map[string]*model.PrivateArtifact{
			"k": {ChannelID: primitive.NewObjectID(), DownloadMode: utils.DownloadModeStrict},
		},
	}

	denied, deniedRecorder := newTestContext(map[string]string{utils.DownloadTokenHeader: "fnd_wrong"})
	DownloadArtifact(denied, repo)

	unknown, unknownRecorder := newTestContext(nil)
	unknown.Request = httptest.NewRequest(http.MethodGet, "/download?key=missing", nil)
	DownloadArtifact(unknown, repo)

	if deniedRecorder.Code != http.StatusNotFound || unknownRecorder.Code != http.StatusNotFound {
		t.Fatalf("got denied=%d unknown=%d, want both 404", deniedRecorder.Code, unknownRecorder.Code)
	}
	if deniedRecorder.Body.String() != unknownRecorder.Body.String() {
		t.Fatalf("bodies differ: denied=%q unknown=%q", deniedRecorder.Body.String(), unknownRecorder.Body.String())
	}
}
