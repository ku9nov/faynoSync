package server

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

var strongSecret = strings.Repeat("k", 44)

func TestValidateSecrets(t *testing.T) {
	tests := []struct {
		name        string
		jwtSecret   string
		apiKey      string
		releaseMode bool
		wantErr     string
	}{
		{name: "empty jwt secret", jwtSecret: "", wantErr: "JWT_SECRET is empty or shorter"},
		{name: "empty jwt secret in release", jwtSecret: "", releaseMode: true, wantErr: "JWT_SECRET is empty or shorter"},
		{name: "short jwt secret", jwtSecret: strings.Repeat("a", minJWTSecretBytes-1), wantErr: "JWT_SECRET is empty or shorter"},
		{name: "minimum length jwt secret", jwtSecret: strings.Repeat("a", minJWTSecretBytes)},
		{name: "strong secrets in release", jwtSecret: strongSecret, apiKey: "Zx81kQ0pWm2rT7vB", releaseMode: true},
		{name: "empty api key in release", jwtSecret: strongSecret, releaseMode: true},
		{name: "dev jwt secret outside release", jwtSecret: "insecure-dev-jwt-secret-do-not-use-in-production"},
		{name: "dev api key outside release", jwtSecret: strongSecret, apiKey: "insecure-dev-api-key"},
		{name: "dev jwt secret in release", jwtSecret: "insecure-dev-jwt-secret-do-not-use-in-production", releaseMode: true, wantErr: "JWT_SECRET holds the public development value"},
		{name: "dev api key in release", jwtSecret: strongSecret, apiKey: "insecure-dev-api-key", releaseMode: true, wantErr: "API_KEY holds the public development value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := viper.New()
			config.Set("JWT_SECRET", tt.jwtSecret)
			config.Set("API_KEY", tt.apiKey)

			err := validateSecrets(config, tt.releaseMode)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
