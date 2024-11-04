# CI/CD Example: Github Actions
This workflow is an example of a CI/CD pipeline for building a Rust application on multiple platforms and uploading assets to `faynoSync`. The workflow updates the version in `Cargo.toml` based on the input provided and handles authentication with faynoSync.

## Prerequisites
You need to create two secrets in your GitHub repository:

- `USERNAME`: Your faynoSync username.

- `PASSWORD`: Your faynoSync password.

## Trigger
Manual Dispatch (workflow_dispatch): Requires a `VERSION` input to set in the `Cargo.toml` file.

### Command example
```
gh workflow run "Build app and upload assets to faynoSync" --ref branch_name --repo github.com/owner_name/repo_name -f VERSION="0.2.5-6"
```