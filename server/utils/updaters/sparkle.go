package updaters

import (
	"fmt"
)

type SparkleUpdater struct {
	Type string `json:"type"`
}

func ValidateSparkleUpdater(updaterType string) error {
	validTypes := []string{"sparkle"}

	for _, validType := range validTypes {
		if updaterType == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid sparkle updater type: %s. Valid types are: %v", updaterType, validTypes)
}

func GetSparkleUpdaterConfig(updaterType string) (*SparkleUpdater, error) {
	if err := ValidateSparkleUpdater(updaterType); err != nil {
		return nil, err
	}

	return &SparkleUpdater{
		Type: updaterType,
	}, nil
}
