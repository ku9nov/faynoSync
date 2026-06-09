package report

import (
	"crypto/sha256"
	"encoding/hex"
	"faynoSync/server/model"
	"strings"
)

func buildGroupHash(app model.ReportApplication, system model.ReportSystem, event model.ReportEvent) string {
	parts := []string{
		app.Name,
		app.Version,
		app.Channel,
		system.Platform,
		system.Arch,
		event.Type,
		event.Reason,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
