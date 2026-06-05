package artifacts

import (
	"fmt"

	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
)

func verifyTrustedRoot(repo *repository.Type) error {
	if err := repo.Root().VerifyDelegate("root", repo.Root()); err != nil {
		return fmt.Errorf("trusted root metadata signature verification failed: %w", err)
	}
	return nil
}

func verifyTrustedTargets(repo *repository.Type) error {
	if err := repo.Root().VerifyDelegate("targets", repo.Targets("targets")); err != nil {
		return fmt.Errorf("trusted targets metadata signature verification failed: %w", err)
	}
	return nil
}

func verifyTrustedDelegatedRole(repo *repository.Type, roleName string) error {
	if err := repo.Targets("targets").VerifyDelegate(roleName, repo.Targets(roleName)); err != nil {
		return fmt.Errorf("trusted %s metadata signature verification failed: %w", roleName, err)
	}
	return nil
}
