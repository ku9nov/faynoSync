package updaters

import (
	"fmt"
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
