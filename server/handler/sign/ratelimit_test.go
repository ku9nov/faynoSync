package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var fixedNow = time.Unix(1_800_000_030, 0)

func setupRateLimitTest(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = time.Now })
	server := miniredis.RunT(t)
	return server, redis.NewClient(&redis.Options{Addr: server.Addr()})
}

// Every lookup fails fast, so Login always ends in 401 once it gets past the rate limits.
func unreachableDatabase(t *testing.T) *mongo.Database {
	t.Helper()
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=20&connectTimeoutMS=20"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Disconnect(context.Background()) })
	return client.Database("test")
}

func doLogin(t *testing.T, db *mongo.Database, rdb *redis.Client, ip, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/login", func(c *gin.Context) { Login(c, db, rdb) })
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func doSignup(t *testing.T, rdb *redis.Client, ip string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/signup", func(c *gin.Context) { SignUp(c, nil, nil, rdb) })
	req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewBufferString(`{"username":"admin","password":"x","api_key":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func loginBody(username string) string {
	return fmt.Sprintf(`{"username":%q,"password":"guess"}`, username)
}

func assertRateLimited(t *testing.T, w *httptest.ResponseRecorder, retryAfter string) {
	t.Helper()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != retryAfter {
		t.Fatalf("expected Retry-After %s, got %q", retryAfter, got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Fatalf("expected JSON error body, got %s", w.Body.String())
	}
}

func TestLoginPerUsernameLimit(t *testing.T) {
	_, rdb := setupRateLimitTest(t)
	db := unreachableDatabase(t)

	for i := int64(0); i < loginPerUsernamePerMinute; i++ {
		w := doLogin(t, db, rdb, fmt.Sprintf("10.0.0.%d", i), loginBody("admin"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	w := doLogin(t, db, rdb, "10.0.1.1", loginBody("admin"))
	assertRateLimited(t, w, "30")
	if strings.Contains(w.Body.String(), "admin") {
		t.Fatalf("response must not echo the username: %s", w.Body.String())
	}

	if w := doLogin(t, db, rdb, "10.0.1.1", loginBody("other")); w.Code != http.StatusUnauthorized {
		t.Fatalf("other username from same IP should not be limited, got %d", w.Code)
	}
}

func TestLoginPerIPLimit(t *testing.T) {
	_, rdb := setupRateLimitTest(t)
	db := unreachableDatabase(t)

	for i := int64(0); i < loginPerIPPerMinute; i++ {
		w := doLogin(t, db, rdb, "10.0.0.1", loginBody(fmt.Sprintf("user%d", i)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	assertRateLimited(t, doLogin(t, db, rdb, "10.0.0.1", loginBody("fresh")), "30")

	if w := doLogin(t, db, rdb, "10.0.0.2", loginBody("fresh")); w.Code != http.StatusUnauthorized {
		t.Fatalf("other IP should not be limited, got %d", w.Code)
	}
}

func TestLoginRejectedByIPDoesNotCountUsername(t *testing.T) {
	server, rdb := setupRateLimitTest(t)
	db := unreachableDatabase(t)

	server.Set(loginIPLimit(ipContext("10.0.0.1")).bucketKey(fixedNow), fmt.Sprint(loginPerIPPerMinute))
	assertRateLimited(t, doLogin(t, db, rdb, "10.0.0.1", loginBody("admin")), "30")

	if server.Exists(loginUsernameLimit("admin").bucketKey(fixedNow)) {
		t.Fatal("username counter must not be touched when the IP limit rejects")
	}
}

func TestLoginBodyStillBound(t *testing.T) {
	_, rdb := setupRateLimitTest(t)
	db := unreachableDatabase(t)

	if w := doLogin(t, db, rdb, "10.0.0.1", "not json"); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d", w.Code)
	}
	if w := doLogin(t, db, rdb, "10.0.0.1", loginBody("admin")); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for valid body, got %d", w.Code)
	}
}

func TestLoginRedisKeysHashUsername(t *testing.T) {
	server, rdb := setupRateLimitTest(t)
	db := unreachableDatabase(t)

	doLogin(t, db, rdb, "10.0.0.1", loginBody("secret-admin-name"))

	keys := server.Keys()
	if len(keys) != 2 {
		t.Fatalf("expected IP and username keys, got %v", keys)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "auth:rl:login:") {
			t.Fatalf("unexpected key prefix: %s", k)
		}
		if strings.Contains(k, "secret-admin-name") {
			t.Fatalf("raw username leaked into key: %s", k)
		}
		if ttl := server.TTL(k); ttl != time.Minute {
			t.Fatalf("expected 1m TTL on %s, got %v", k, ttl)
		}
	}
}

func TestResetRateLimit(t *testing.T) {
	server, rdb := setupRateLimitTest(t)

	limit := loginUsernameLimit("admin")
	server.Set(limit.bucketKey(fixedNow), "4")
	resetRateLimit(context.Background(), rdb, limit, fixedNow)

	if server.Exists(limit.bucketKey(fixedNow)) {
		t.Fatal("username counter should be removed after a successful login")
	}
}

func TestLoginRedisErrorFailsClosed(t *testing.T) {
	server, rdb := setupRateLimitTest(t)
	db := unreachableDatabase(t)
	server.Close()

	if w := doLogin(t, db, rdb, "10.0.0.1", loginBody("admin")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on Redis error, got %d", w.Code)
	}
}

func TestSignupPerIPLimit(t *testing.T) {
	_, rdb := setupRateLimitTest(t)
	t.Setenv("API_KEY", "right")

	for i := int64(0); i < signupPerIPPerHour; i++ {
		if w := doSignup(t, rdb, "10.0.0.1"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}
	assertRateLimited(t, doSignup(t, rdb, "10.0.0.1"), "3570")

	if w := doSignup(t, rdb, "10.0.0.2"); w.Code != http.StatusUnauthorized {
		t.Fatalf("other IP should not be limited, got %d", w.Code)
	}
}

func TestSignupGlobalLimit(t *testing.T) {
	_, rdb := setupRateLimitTest(t)
	t.Setenv("API_KEY", "right")

	for i := int64(0); i < signupGlobalPerHour; i++ {
		if w := doSignup(t, rdb, fmt.Sprintf("10.0.0.%d", i)); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}
	assertRateLimited(t, doSignup(t, rdb, "10.0.1.1"), "3570")
}

func TestSignupRedisErrorFailsClosed(t *testing.T) {
	server, rdb := setupRateLimitTest(t)
	t.Setenv("API_KEY", "right")
	server.Close()

	if w := doSignup(t, rdb, "10.0.0.1"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on Redis error, got %d", w.Code)
	}
}

func TestSignupEmptyAPIKeyRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("API_KEY", "")

	router := gin.New()
	router.POST("/signup", func(c *gin.Context) { SignUp(c, nil, nil, nil) })
	req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewBufferString(`{"username":"admin","password":"x"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with empty API_KEY, got %d", w.Code)
	}
}

func ipContext(ip string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.RemoteAddr = ip + ":1234"
	return c
}

func TestClientIPKeyGroupsIPv6By64(t *testing.T) {
	a := clientIPKey(ipContext("[2001:db8:1:2:aaaa::1]"))
	b := clientIPKey(ipContext("[2001:db8:1:2:bbbb::2]"))
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("expected shared /64 bucket, got %s and %s", a, b)
	}
	if got := clientIPKey(ipContext("10.0.0.1")); got != "10.0.0.1" {
		t.Fatalf("expected IPv4 unchanged, got %s", got)
	}
}
