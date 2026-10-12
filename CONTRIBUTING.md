# Contributing to faynoSync

Thanks for your interest in faynoSync. Bug reports, documentation fixes, and code contributions are welcome.

## Reporting bugs and requesting features

Use [GitHub Issues](https://github.com/ku9nov/faynoSync/issues) and pick the matching template (bug report, feature request, documentation request). Search existing issues first.

Security problems must not be reported in public issues. See [SECURITY.md](SECURITY.md).

## Development workflow

- `main` holds released code. `development` is the integration branch.
- Fork the repository, create a branch from `development`, and open a pull request against `development`.
- Releases are cut by the maintainer through a pull request from `development` to `main`.
- For larger changes, open an issue first to agree on the approach.

Local setup (Docker Compose or running from source) is described in the [README](README.md) and the [Local Setup guide](https://faynosync.com/docs/getting-started/local-deploy).

## Requirements for a pull request

### Tests

New functionality and bug fixes must come with tests:

- New features add tests that cover the new behavior.
- Bug fixes add a regression test that fails without the fix.
- Unit tests live next to the code (`*_test.go` under `server/`). Use mocks for databases in unit tests.
- Integration tests (`faynoSync_test.go`) run against real MongoDB, Redis, and S3-compatible storage. Do not mock the database there.

Before opening a pull request, run:

```shell
go test ./server/... -race
```

and the integration tests, either from source against the containerized dependencies:

```shell
cp .env.example .env
docker compose up -d db cache s3 webui
go test
```

or inside the Docker Compose stack, as CI does:

```shell
docker compose up --build -d
docker compose exec -T backend /usr/bin/faynoSync migrate up
docker compose exec -T backend /usr/bin/faynoSync_tests
```

Integration tests share state and depend on order: run the whole suite, not a single test with `-run`.

### Code style

Go:

- Format with `gofmt`, and make sure `go vet ./...` passes.
- Naming: camelCase for variables and functions, PascalCase for exported types, uppercase abbreviations (`apiURL`, not `apiUrl`).
- Logging goes through `logrus`, not `fmt`.
- Keep comments for the non-obvious "why".

Dashboard (`dashboard/`):

- `yarn lint` must pass with zero warnings, and `yarn build` must succeed.

### Security-sensitive code

Changes to TUF metadata, signing, expiration, versioning, or metadata caching must not weaken verification: signatures and thresholds are always checked, expired metadata is never trusted, and versions only increase. Describe the security impact in the pull request.

### Pull request description

Describe user-facing changes (behavior, API, environment variables) in the pull request. The maintainer updates [CHANGELOG.md](CHANGELOG.md) and the [documentation site](https://faynosync.com/docs/intro).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
