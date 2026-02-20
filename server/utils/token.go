package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	APITokenPrefix       = "fns_"
	apiTokenRandomLength = 32
	apiTokenPrefixLength = 8
)

func GenerateAPIToken() (string, string, string, error) {
	randomBytes := make([]byte, apiTokenRandomLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	randomHex := hex.EncodeToString(randomBytes)
	token := APITokenPrefix + randomHex
	tokenPrefix := APITokenPrefix + randomHex[:apiTokenPrefixLength]

	return token, tokenPrefix, HashAPIToken(token), nil
}

func HashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func IsAPIToken(token string) bool {
	return strings.HasPrefix(token, APITokenPrefix)
}
