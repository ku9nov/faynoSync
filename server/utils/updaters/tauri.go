package updaters

import (
	"fmt"
	"sort"
	"strings"
)

// TauriUpdater represents the Tauri updater configuration
type TauriUpdater struct {
	Type string `json:"type"`
}

// ValidateTauriUpdater validates tauri updater configuration
func ValidateTauriUpdater(updaterType string) error {
	validTypes := []string{"tauri"}

	for _, validType := range validTypes {
		if updaterType == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid tauri updater type: %s. Valid types are: %v", updaterType, validTypes)
}

// GetTauriUpdaterConfig returns tauri updater configuration
func GetTauriUpdaterConfig(updaterType string) (*TauriUpdater, error) {
	if err := ValidateTauriUpdater(updaterType); err != nil {
		return nil, err
	}

	return &TauriUpdater{
		Type: updaterType,
	}, nil
}

type TauriParamValidator struct {
	updaterType string
}

func (v *TauriParamValidator) ValidateParams(params map[string]interface{}) error {
	signature, exists := params["signature"]
	if !exists || signature == "" {
		return fmt.Errorf("tauri updater requires a signature parameter for update functionality. Please include a signature in your request")
	}
	return nil
}

func (v *TauriParamValidator) GetUpdaterType() string {
	return v.updaterType
}

type NoOpParamValidator struct {
	updaterType string
}

func (v *NoOpParamValidator) ValidateParams(params map[string]interface{}) error {
	return nil
}

func (v *NoOpParamValidator) GetUpdaterType() string {
	return v.updaterType
}

var tauriPayloadPriority = []string{
	"app.tar.gz",
	"appimage.tar.gz",
	"nsis.zip",
	"msi.zip",
	"gz",
	"zip",
	"exe",
	"msi",
	"appimage",
}

// tauriUpdateURL picks the update_url_* the Tauri updater should download. Signature
// files are never a payload; any other package is a deterministic last resort.
func tauriUpdateURL(response map[string]interface{}) (string, bool) {
	candidates := map[string]string{}
	for key, value := range response {
		url, ok := value.(string)
		if !ok || !strings.HasPrefix(key, "update_url") {
			continue
		}
		pkg := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(key, "update_url"), "_"))
		if pkg == "sig" {
			continue
		}
		candidates[pkg] = url
	}

	for _, pkg := range tauriPayloadPriority {
		if url, ok := candidates[pkg]; ok {
			return url, true
		}
	}

	remaining := make([]string, 0, len(candidates))
	for pkg := range candidates {
		remaining = append(remaining, pkg)
	}
	if len(remaining) == 0 {
		return "", false
	}
	sort.Strings(remaining)
	return candidates[remaining[0]], true
}
