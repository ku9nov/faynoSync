package delegations

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func repoWithTargetsAndDelegations(roleName string, initialPaths []string) *repository.Type {
	repo := repository.New()
	expires := time.Now().Add(365 * 24 * time.Hour)
	targets := metadata.Targets(expires)
	targets.Signed.Delegations = &metadata.Delegations{
		Keys:  map[string]*metadata.Key{},
		Roles: []metadata.DelegatedRole{{Name: roleName, KeyIDs: []string{"k1"}, Threshold: 1, Paths: initialPaths}},
	}
	repo.SetTargets("targets", targets)
	return repo
}

// repoWithTargetsNoDelegations returns a repo with targets set but no Delegations.
func repoWithTargetsNoDelegations() *repository.Type {
	repo := repository.New()
	targets := metadata.Targets(time.Now().Add(24 * time.Hour))
	// Delegations left nil
	repo.SetTargets("targets", targets)
	return repo
}

// repoWithTargetsDelegationsRolesNil returns a repo with targets and Delegations set but Roles nil.
func repoWithTargetsDelegationsRolesNil() *repository.Type {
	repo := repository.New()
	targets := metadata.Targets(time.Now().Add(24 * time.Hour))
	targets.Signed.Delegations = &metadata.Delegations{Keys: map[string]*metadata.Key{}, Roles: nil}
	repo.SetTargets("targets", targets)
	return repo
}

// repoWithNoTargets returns a repo that has not had SetTargets("targets", ...) called.
func repoWithNoTargets() *repository.Type {
	return repository.New()
}

func getRolePaths(repo *repository.Type, roleName string) []string {
	targets := repo.Targets("targets")
	if targets == nil || targets.Signed.Delegations == nil || targets.Signed.Delegations.Roles == nil {
		return nil
	}
	for i := range targets.Signed.Delegations.Roles {
		if targets.Signed.Delegations.Roles[i].Name == roleName {
			return targets.Signed.Delegations.Roles[i].Paths
		}
	}
	return nil
}

func pathSliceContains(paths []string, p string) bool {
	for _, q := range paths {
		if q == p {
			return true
		}
	}
	return false
}

// To verify: In UpdateDelegationPaths change the condition so repo.Targets("targets") nil is not treated as error; test will fail (no error or wrong message).
func TestUpdateDelegationPaths_TargetsNotLoaded(t *testing.T) {
	ctx := context.Background()
	repo := repoWithNoTargets()

	updated, err := UpdateDelegationPaths(ctx, repo, "myrole", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, updated)
	assert.Contains(t, err.Error(), "targets metadata not loaded")
}

// To verify: In UpdateDelegationPaths skip the check for delegations == nil; test will fail (panic or wrong error).
func TestUpdateDelegationPaths_NoDelegations(t *testing.T) {
	ctx := context.Background()
	repo := repoWithTargetsNoDelegations()

	updated, err := UpdateDelegationPaths(ctx, repo, "myrole", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, updated)
	assert.Contains(t, err.Error(), "no custom delegations found")
}

// To verify: In UpdateDelegationPaths skip the check for delegations.Roles == nil; test will fail (panic or wrong error).
func TestUpdateDelegationPaths_DelegationsRolesNil(t *testing.T) {
	ctx := context.Background()
	repo := repoWithTargetsDelegationsRolesNil()

	updated, err := UpdateDelegationPaths(ctx, repo, "myrole", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, updated)
	assert.Contains(t, err.Error(), "no custom delegations found")
}

// To verify: In UpdateDelegationPaths change role lookup so a wrong name is accepted; test will fail (no error or wrong message).
func TestUpdateDelegationPaths_RoleNotFound(t *testing.T) {
	ctx := context.Background()
	repo := repoWithTargetsAndDelegations("existing-role", []string{"x"})

	updated, err := UpdateDelegationPaths(ctx, repo, "nonexistent", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, updated)
	assert.Contains(t, err.Error(), "delegation role nonexistent not found")
}

// To verify: In UpdateDelegationPaths change exact match logic so existing path is treated as new; test will fail (updated true or path duplicated).
func TestUpdateDelegationPaths_AllPathsExactMatch_ReturnsFalseNoChange(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	existingPath := "foo/bar"
	repo := repoWithTargetsAndDelegations(roleName, []string{existingPath})

	updated, err := UpdateDelegationPaths(ctx, repo, roleName, []string{existingPath}, "admin")

	require.NoError(t, err)
	assert.False(t, updated, "should not report update when all paths already exist (exact match)")
	paths := getRolePaths(repo, roleName)
	require.Len(t, paths, 1)
	assert.Equal(t, existingPath, paths[0])
}

// To verify: In UpdateDelegationPaths skip adding new path when !exactMatch; test will fail (updated false or path missing).
func TestUpdateDelegationPaths_AddNewPath_ReturnsTrueAndPathAdded(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	existingPath := "a"
	newPath := "b"
	repo := repoWithTargetsAndDelegations(roleName, []string{existingPath})

	updated, err := UpdateDelegationPaths(ctx, repo, roleName, []string{newPath}, "admin")

	require.NoError(t, err)
	assert.True(t, updated)
	paths := getRolePaths(repo, roleName)
	require.True(t, pathSliceContains(paths, newPath), "new path %q should be in role paths: %v", newPath, paths)
	assert.True(t, pathSliceContains(paths, existingPath), "existing path should remain")
}

// To verify: In UpdateDelegationPaths do not add full path when artifactPath has prefix match; test will fail (path "foo/bar" missing).
func TestUpdateDelegationPaths_PrefixMatch_AddsFullPath(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"foo/"})

	updated, err := UpdateDelegationPaths(ctx, repo, roleName, []string{"foo/bar"}, "admin")

	require.NoError(t, err)
	assert.True(t, updated)
	paths := getRolePaths(repo, roleName)
	assert.True(t, pathSliceContains(paths, "foo/bar"), "full path foo/bar should be added: %v", paths)
}

// To verify: In UpdateDelegationPaths change behavior for empty artifactPaths (e.g. return error); test will fail (wrong return).
func TestUpdateDelegationPaths_EmptyArtifactPaths_ReturnsFalseNoError(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"a"})

	updated, err := UpdateDelegationPaths(ctx, repo, roleName, []string{}, "admin")

	require.NoError(t, err)
	assert.False(t, updated)
	paths := getRolePaths(repo, roleName)
	assert.Len(t, paths, 1)
	assert.Equal(t, "a", paths[0])
}

// To verify: In UpdateDelegationPaths add duplicate paths to role; test will fail (duplicate in Paths).
func TestUpdateDelegationPaths_DuplicateInInput_AddedOnce(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	newPath := "only-one"
	repo := repoWithTargetsAndDelegations(roleName, []string{})

	updated, err := UpdateDelegationPaths(ctx, repo, roleName, []string{newPath, newPath}, "admin")

	require.NoError(t, err)
	assert.True(t, updated)
	paths := getRolePaths(repo, roleName)
	count := 0
	for _, p := range paths {
		if p == newPath {
			count++
		}
	}
	assert.Equal(t, 1, count, "path should appear only once: %v", paths)
}

// To verify: In UpdateDelegationPaths change logic so repo is not updated via SetTargets; test will fail (paths not updated in repo).
func TestUpdateDelegationPaths_MultipleNewPaths_AllAddedAndRepoUpdated(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"existing"})
	newPaths := []string{"p1", "p2", "p3"}

	updated, err := UpdateDelegationPaths(ctx, repo, roleName, newPaths, "admin")

	require.NoError(t, err)
	assert.True(t, updated)
	paths := getRolePaths(repo, roleName)
	require.True(t, pathSliceContains(paths, "existing"))
	for _, p := range newPaths {
		assert.True(t, pathSliceContains(paths, p), "path %q should be in role: %v", p, paths)
	}
}

// --- RemoveDelegationPaths tests ---

// To verify: In RemoveDelegationPaths skip the check for targets == nil; test will fail (panic or wrong error).
func TestRemoveDelegationPaths_TargetsNotLoaded(t *testing.T) {
	ctx := context.Background()
	repo := repoWithNoTargets()

	removed, err := RemoveDelegationPaths(ctx, repo, "myrole", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "targets metadata not loaded")
}

// To verify: In RemoveDelegationPaths skip the check for delegations == nil; test will fail (panic or wrong error).
func TestRemoveDelegationPaths_NoDelegations(t *testing.T) {
	ctx := context.Background()
	repo := repoWithTargetsNoDelegations()

	removed, err := RemoveDelegationPaths(ctx, repo, "myrole", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "no custom delegations found")
}

// To verify: In RemoveDelegationPaths skip the check for delegations.Roles == nil; test will fail (panic or wrong error).
func TestRemoveDelegationPaths_DelegationsRolesNil(t *testing.T) {
	ctx := context.Background()
	repo := repoWithTargetsDelegationsRolesNil()

	removed, err := RemoveDelegationPaths(ctx, repo, "myrole", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "no custom delegations found")
}

// To verify: In RemoveDelegationPaths change role lookup so a wrong name is accepted; test will fail (no error or wrong message).
func TestRemoveDelegationPaths_RoleNotFound(t *testing.T) {
	ctx := context.Background()
	repo := repoWithTargetsAndDelegations("existing-role", []string{"x"})

	removed, err := RemoveDelegationPaths(ctx, repo, "nonexistent", []string{"a/b"}, "admin")

	require.Error(t, err)
	assert.False(t, removed)
	assert.Contains(t, err.Error(), "delegation role nonexistent not found")
}

// To verify: In RemoveDelegationPaths skip exact path removal or SetTargets; test will fail (removed false or path still present).
func TestRemoveDelegationPaths_RemoveExactPath_ReturnsTrueAndPathRemoved(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"a", "b"})

	removed, err := RemoveDelegationPaths(ctx, repo, roleName, []string{"a"}, "admin")

	require.NoError(t, err)
	assert.True(t, removed)
	paths := getRolePaths(repo, roleName)
	assert.False(t, pathSliceContains(paths, "a"), "path a should be removed: %v", paths)
	assert.True(t, pathSliceContains(paths, "b"), "path b should remain: %v", paths)
}

// To verify: In RemoveDelegationPaths remove non-existent path (e.g. return true); test will fail (removed true or paths changed).
func TestRemoveDelegationPaths_RemoveNonExistentPath_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"a"})

	removed, err := RemoveDelegationPaths(ctx, repo, roleName, []string{"b"}, "admin")

	require.NoError(t, err)
	assert.False(t, removed)
	paths := getRolePaths(repo, roleName)
	require.Len(t, paths, 1)
	assert.Equal(t, "a", paths[0])
}

// To verify: In RemoveDelegationPaths change behavior for empty artifactPaths (e.g. return true); test will fail (wrong return).
func TestRemoveDelegationPaths_EmptyArtifactPaths_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"a", "b"})

	removed, err := RemoveDelegationPaths(ctx, repo, roleName, []string{}, "admin")

	require.NoError(t, err)
	assert.False(t, removed)
	paths := getRolePaths(repo, roleName)
	assert.Len(t, paths, 2)
	assert.True(t, pathSliceContains(paths, "a"))
	assert.True(t, pathSliceContains(paths, "b"))
}

// To verify: In RemoveDelegationPaths remove only one occurrence per path or skip SetTargets; test will fail (wrong paths).
func TestRemoveDelegationPaths_RemoveMultiplePaths_ReturnsTrueAndRepoUpdated(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"a", "b", "c"})

	removed, err := RemoveDelegationPaths(ctx, repo, roleName, []string{"a", "c"}, "admin")

	require.NoError(t, err)
	assert.True(t, removed)
	paths := getRolePaths(repo, roleName)
	require.Len(t, paths, 1)
	assert.Equal(t, "b", paths[0])
}

// To verify: In RemoveDelegationPaths do not remove path when only prefix matches; test will fail (path "foo" removed).
func TestRemoveDelegationPaths_OnlyExactMatchRemoved_PrefixNotRemoved(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"foo", "foo/bar"})

	removed, err := RemoveDelegationPaths(ctx, repo, roleName, []string{"foo/bar"}, "admin")

	require.NoError(t, err)
	assert.True(t, removed)
	paths := getRolePaths(repo, roleName)
	assert.True(t, pathSliceContains(paths, "foo"), "prefix path foo should remain: %v", paths)
	assert.False(t, pathSliceContains(paths, "foo/bar"), "foo/bar should be removed: %v", paths)
}

// To verify: In RemoveDelegationPaths change iteration order (e.g. forward) so slice removal is wrong; test may fail (wrong remaining paths).
func TestRemoveDelegationPaths_RemoveFromMiddle_AllRemovedCorrectly(t *testing.T) {
	ctx := context.Background()
	roleName := "myrole"
	repo := repoWithTargetsAndDelegations(roleName, []string{"first", "middle", "last"})

	removed, err := RemoveDelegationPaths(ctx, repo, roleName, []string{"middle"}, "admin")

	require.NoError(t, err)
	assert.True(t, removed)
	paths := getRolePaths(repo, roleName)
	require.Len(t, paths, 2)
	assert.True(t, pathSliceContains(paths, "first"))
	assert.True(t, pathSliceContains(paths, "last"))
}
