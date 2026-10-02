package server

import (
	"fmt"
	"net/http"
	"time"
)

func Healthcheck(port string) error {
	if port == "" {
		port = "9000"
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck failed: /health returned %d", resp.StatusCode)
	}
	return nil
}
