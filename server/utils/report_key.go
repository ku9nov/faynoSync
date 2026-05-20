package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	ReportKeyPrefix       = "rpk_"
	reportKeyRandomLength = 32
)

func GenerateReportKey() (string, error) {
	randomBytes := make([]byte, reportKeyRandomLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate report key bytes: %w", err)
	}

	return ReportKeyPrefix + hex.EncodeToString(randomBytes), nil
}
