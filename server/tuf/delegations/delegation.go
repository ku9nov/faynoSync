package delegations

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func UpdateDelegationPaths(
	ctx context.Context,
	repo *repository.Type,
	roleName string,
	artifactPaths []string,
	adminName string,
) (bool, error) {
	targets := repo.Targets("targets")
	if targets == nil {
		return false, fmt.Errorf("targets metadata not loaded")
	}

	delegations := targets.Signed.Delegations
	if delegations == nil || delegations.Roles == nil {
		return false, fmt.Errorf("no custom delegations found in targets metadata")
	}

	var targetRole *metadata.DelegatedRole
	for i := range delegations.Roles {
		if delegations.Roles[i].Name == roleName {
			targetRole = &delegations.Roles[i]
			break
		}
	}

	if targetRole == nil {
		return false, fmt.Errorf("delegation role %s not found", roleName)
	}

	newPaths := make(map[string]bool)
	for _, artifactPath := range artifactPaths {
		exactMatch := false
		prefixMatch := false

		for _, existingPath := range targetRole.Paths {
			if existingPath == artifactPath {
				exactMatch = true
				break
			}
		}

		if !exactMatch {
			for _, existingPath := range targetRole.Paths {
				if strings.HasPrefix(artifactPath, existingPath) {
					prefixMatch = true
					break
				}
			}

			// Add the full artifact path to paths even if prefix matches
			// This allows for more granular control
			newPaths[artifactPath] = true
			if prefixMatch {
				logrus.Debugf("Artifact path %s matches prefix pattern but exact path not found, will add full path to delegation role", artifactPath)
			} else {
				logrus.Debugf("Artifact path %s doesn't match any existing patterns, will add full path to delegation role", artifactPath)
			}
		}
	}

	if len(newPaths) == 0 {
		logrus.Debugf("All artifact paths match existing patterns for role %s", roleName)
		return false, nil
	}

	for newPath := range newPaths {
		// Check if path already exists (avoid duplicates)
		exists := false
		for _, existingPath := range targetRole.Paths {
			if existingPath == newPath {
				exists = true
				break
			}
		}
		if !exists {
			targetRole.Paths = append(targetRole.Paths, newPath)
			logrus.Infof("Added new path pattern %s to delegation role %s", newPath, roleName)
		}
	}

	repo.SetTargets("targets", targets)

	logrus.Debugf("Successfully updated delegation paths for role %s (targets metadata will be saved by caller)", roleName)
	return true, nil
}

func RemoveDelegationPaths(
	ctx context.Context,
	repo *repository.Type,
	roleName string,
	artifactPaths []string,
	adminName string,
) (bool, error) {
	targets := repo.Targets("targets")
	if targets == nil {
		return false, fmt.Errorf("targets metadata not loaded")
	}

	delegations := targets.Signed.Delegations
	if delegations == nil || delegations.Roles == nil {
		return false, fmt.Errorf("no custom delegations found in targets metadata")
	}

	var targetRole *metadata.DelegatedRole
	for i := range delegations.Roles {
		if delegations.Roles[i].Name == roleName {
			targetRole = &delegations.Roles[i]
			break
		}
	}

	if targetRole == nil {
		return false, fmt.Errorf("delegation role %s not found", roleName)
	}

	pathsRemoved := false
	for _, artifactPath := range artifactPaths {
		// Remove exact path match from targetRole.Paths
		for i := len(targetRole.Paths) - 1; i >= 0; i-- {
			if targetRole.Paths[i] == artifactPath {
				targetRole.Paths = append(targetRole.Paths[:i], targetRole.Paths[i+1:]...)
				pathsRemoved = true
				logrus.Infof("Removed path pattern %s from delegation role %s", artifactPath, roleName)
				break
			}
		}
	}

	if !pathsRemoved {
		logrus.Debugf("No paths were removed for role %s (paths may not have existed or were prefixes)", roleName)
		return false, nil
	}

	repo.SetTargets("targets", targets)

	logrus.Debugf("Successfully removed delegation paths for role %s (targets metadata will be saved by caller)", roleName)
	return true, nil
}
