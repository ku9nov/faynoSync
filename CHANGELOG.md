# Changelog

## v1.6.3

### Features

- Added Redis caching for `squirrel_windows` updater responses, including the rewritten `RELEASES` feed served as a raw `text/plain` body (filename column rewritten to absolute storage URLs so Squirrel downloads each `.nupkg` directly from storage).
- Added the `updater` parameter to the edge CDN object key so edge responses are cached per updater.

### Fixes

- Team users now store artifacts under their admin: `UpdateSpecificApp` resolves the request owner via `ResolveRequestOwner` before uploading to S3.
- `.blockmap` and `.nupkg` artifacts are now excluded from the `checkLatest` response since they are derived by updaters (electron-builder from the `.yml`, Squirrel from the `RELEASES` feed) and must not be returned.

### Security

- Updated `go.mongodb.org/mongo-driver` to 1.17.7.
- Bumped `github.com/ku9nov/faynosync-sdk-go` to 0.2.0.

## v1.6.2

### Security

- Updated Go to 1.26.3 (`go.mod`, `Dockerfile`, CI workflow) to fix stdlib CVE-2026-* issues.
- Updated `golang.org/x/crypto` to 0.52.0 to fix CVE-2026-* issues.
- Updated `golang.org/x/net` to 0.55.0 to fix CVE-2026-* issues.

## v1.6.1

### Fixes

- Fixed version parsing on the latest-version check: `-` separators in the `version` query parameter are now normalized to `.` so values like `1-2-3` are parsed correctly.

### Dependencies

- Bumped `tsx` to `^4.22.4` in the `tuf-client-ts` example, pulling in `esbuild` >=0.28.1 and resolving two Dependabot alerts (dev-only, example code).

## v1.6.0

### Features

- Added a crash/event reporting API: clients can ingest reports, which are deduplicated into groups by signature hash, with detail blobs stored in the private S3 bucket and served via presigned URLs.
- Added report endpoints for ingest, group listing, group details, and presigned blob access.
- Added per-key, per-group, and per-device+group rate limiting on report ingest.
- Added report partitioning by app and supporting MongoDB indexes via new migrations.
- Added `REPORTS_*` configuration (enable flag, body/blob size limits, blob retention, max blobs per group, storage prefix, rate limit).

## v1.5.17

### Security (TUF)

- Fixed delegated key rotation failing at the delegated-signing step; the rollback floor now derives from the trusted snapshot (`root → snapshot`) instead of re-verifying the orphaned old delegated blob through the just-rotated targets delegator.
- Fixed trusted metadata read back from S3 without re-verifying its signature; all loaders now verify signature + expiration against the root chain before any authorization/version decision.
- Fixed timestamp version rollback on a transient S3 download error; version is only reset to 1 when the object provably does not exist.
- Fixed inconsistent locking across the snapshot/timestamp update paths; all three now run inside a single token-checked per-(admin,app) lock.
- Fixed `AddArtifacts`/`RemoveArtifacts` mutating root/targets/delegated metadata loaded from S3 without verifying signatures first.
- Fixed target hashes accepted without format validation; a well-formed 32-byte `sha256` is now required (invalid-hex raw-bytes fallback removed, non-positive lengths rejected).
- Fixed unbounded expiration values from config/bootstrap; per-role bounds are now enforced (`timestamp ≤ snapshot ≤ targets ≤ root`).

## v1.5.16

### Security (TUF)

- Fixed snapshot lock key inconsistency that allowed concurrent artifact publish and force-online update to race and silently discard each other's snapshot changes.
- Fixed silent verification skip in `PostMetadataSign` targets path: S3/unmarshal failures now surface as errors instead of being swallowed, preventing unverified metadata from advancing.
- Fixed trusted metadata loaded from S3 without expiration check; expired metadata is now rejected before use.
- Fixed root rotation staging that used fragile error string matching to detect wrong-version vs bad-signature failures.
- Fixed `PostMetadataSign` Redis writes silently ignored on staging paths; errors are now propagated.
- Fixed `loadTrustedRootMetadataFromS3` using raw `json.Unmarshal` instead of the library's `FromFile`; root is now loaded through the verified library path.

### Fixes (TUF)

- Fixed snapshot `MetaFile` entries omitting hashes; snapshot now includes `sha256` hash and length for all referenced metadata files.
- Fixed missing root signature verification in the `thresholdReached` targets signing path.
- Fixed `GetConfig` returning only the first custom role expiration due to a loop variable bug.
- Fixed `RemoveArtifacts` loading root by hardcoded version 1 instead of the latest version.
- Fixed duplicate signing logic in `removeArtifactsFromDelegatedRole`.
- Fixed MongoDB artifact status updated before TUF operation succeeds; status is now written only after a successful TUF commit.
- Fixed temporary directories created in `cwd` instead of system temp.
- Fixed `HelperGetPathForTarget` panicking on `os.Getwd()` failure; returns error instead.
- Fixed task records stored in Redis with no TTL.
- Fixed `CalculateExpirationDays` silently returning 365 on parse failure; returns error instead.
- Removed unused `ctx context.Context` parameter from delegation helpers.

### Improvements (TUF)

- Added `appName` validation to reject characters that could cause Redis key collisions or S3 path injection.
- Replaced `KEYS` with `SCAN` in `GetMetadataSign` to avoid blocking Redis on large keyspaces.
- Fixed `GetConfig` loop and `PutConfig` to respect online/offline mode for targets expiration.
- Removed dead code: `GetBootstrapLocks`, `bootstrap()`, `bootstrapFinalize()`.

## v1.5.15

### Features

- Added `cdn` parameter to `POST /app/create` and `POST /app/update` endpoints, plus `S3_BUCKET_NAME_CDN` for CDN-targeted uploads.
- Added batch object deletion support in storage clients to clean up related artifacts more efficiently.
- Updated test setup to use SDK-backed integration flow.
- Added telemetry beacon endpoint `/telemetry/beacon` to collect beacon requests and build allow-list index.

### Fixes

- Fixed telemetry does not work when performance mode is enabled.

## v1.5.14

### Features

- Added `reports` parameter to `POST /app/create` and `POST /app/update` endpoints.
- When `reports` is enabled, a public report key is created in the `report_keys` collection and bound to the app (one key per app).
- Toggling `reports` on app update creates or removes the report key binding when the flag changes.
- Added `GET /report-keys/list` to list report keys with app identity for the current owner (team users see only allowed apps).
- Added `POST /report-keys/regenerate` to replace the report key value for a given app.

### Database

- Added `report_keys` collection indexes: unique `app_id` and owner lookup for listing.

### Maintenance

- Added integration tests: `TestListReportKeys`, `TestListReportKeysNoValues`, `TestListReportKeysWithSecondaryUser`, `TestListReportKeysAdminUserBeforeTeamUser`, `TestListReportKeysTeamUserPermissionDenied`, `TestListReportKeysTeamUser`, `TestRegenerateReportKey`, `TestFailedRegenerateReportKeyWithSecondaryUser`, `TestFailedRegenerateReportKeyWithTeamUser`, `TestRegenerateReportKeyTeamUser`, `TestListReportKeysNoValuesAfterUpdateAppReportsToFalse`.

## v1.5.13

### Features

- Added `POST /tuf/v1/metadata/delegated/rotate` to rotate delegated targets metadata.

### Maintenance

- Upgraded `github.com/slack-go/slack` from v0.14.0 to v0.23.1.
- Refactored the TUF metadata package by moving shared helpers and rotation orchestration from `metadata.go` into `metadata_utils.go`.
- Added `metadata_delegated_rotate_test.go` covering delegated rotation staging and related error paths.

### API Tooling

- Updated the Postman collection with requests for delegated metadata rotation.

## v1.5.12

### Improvements

- Decoupled MongoDB migrations from API startup: the server now starts with `./faynoSync` only, and migrations run explicitly via `./faynoSync migrate up` or `./faynoSync migrate down`.

### Features

- Added `GET /tuf/v1/metadata/targets` and `GET /tuf/v1/metadata/delegated` endpoints to retrieve TUF metadata for targets and delegated roles.
- Added tuf typescript example.

### Fixes

- Fixed telemetry period aggregation for `range=week` and `range=month` to deduplicate repeated `client_id` values across days instead of summing daily set sizes.
- Updated telemetry integration coverage to validate that `unique_clients`, `clients_using_latest_version`, and `clients_outdated` remain deduplicated at period level.


## v1.5.11

### Features

- Added `POST /tuf/v1/bootstrap/recovery` to rebuild bootstrap Redis settings from persisted TUF metadata for already initialized repositories.
- Added asynchronous `bootstrap_recovery` task flow with lock protection, recovery prechecks, timeout support, and task status reporting.

### Security & Access Control

- Added RBAC edit permission checks for TUF task status, artifact publish, and artifact delete endpoints.
- Added owner resolution middleware for team users so TUF artifact operations run under resolved owner context.

### Reliability

- Unified bootstrap settings persistence and recovery via a shared Redis save path, including delegated role expirations and `ROOT_SIGNING` initialization.

### API Tooling

- Updated Postman collection with bootstrap recovery API request examples.

## v1.5.10

### Dependencies

- Upgraded `go.opentelemetry.io/otel`, `go.opentelemetry.io/otel/metric`, `go.opentelemetry.io/otel/sdk`, `go.opentelemetry.io/otel/sdk/metric`, and `go.opentelemetry.io/otel/trace` to `v1.43.0`.

### Security & Signing Improvements

- Extended TUF online signing to support multiple key types (Ed25519, ECDSA, and RSA-PSS) loaded from filesystem private keys.
- Added signer/verifier construction by key type with explicit keyid-to-key-material validation to prevent mismatched key usage.

### Maintenance

- Removed legacy bootstrap generation API surface (`/tuf/v1/bootstrap/generate` and `/tuf/v1/bootstrap/locks`) and deleted obsolete generate handlers/tests.

## v1.5.9

### Dependencies

- Upgraded `github.com/aws/aws-sdk-go-v2/service/s3` to `v1.97.3`.
- Upgraded `github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream` to `v1.7.8`.

## v1.5.8

### Dependencies

- Upgraded `github.com/go-jose/go-jose/v4` to `v4.1.4`.

## v1.5.7

### Dependencies

- Upgraded Go to v1.26.1.
- Upgraded `google.golang.org/grpc` to v1.79.3.

## v1.5.6

### Maintenance

- Migrated from MinIO to Garage for default local S3 storage.

## v1.5.5

### Features

- Slack notifications now reuse a single mutable message per app version across artifact create, update, and delete flows, with Redis-backed state, configurable TTL, and cleanup when a version is deleted.

## v1.5.4

### Dependencies

- Upgraded `go.opentelemetry.io/otel/sdk` to v1.40.0.

### Improvements

- Token create endpoint: changed response status code for token creation.

## v1.5.3

### Features

- **API Tokens**: Added API tokens for secure and scoped access to the API.

### Testing

- **API Tokens integration tests**: Added integration tests for creating, listing, and deleting API tokens.

## v1.5.2

* **New Features**
  * Added multi-signer support for secure cryptographic operations across roles
  * Introduced per-role key threshold configuration for enhanced key management
  * Enhanced bootstrap process with conflict detection and persistent metadata validation

* **Improvements**
  * More detailed error messages including per-key failure information
  * Better root metadata versioning with intelligent fallback logic
  * Added context-aware cancellation support and improved compatibility with large datasets

## v1.5.1

### Bug Fixes

- **Fixed incorrect key usage in metadata signing**: Each TUF role (snapshot, targets, delegated roles) now uses its own dedicated key for signing instead of incorrectly using the timestamp key. This ensures proper TUF specification compliance.

### Features

- **Online metadata update endpoint**: Added `POST /tuf/v1/metadata/online` endpoint for force updating online metadata roles (snapshot, timestamp, targets, delegated roles) without requiring offline signing workflow.

- **Metadata sign deletion endpoint**: Added `POST /tuf/v1/metadata/sign/delete` endpoint for deleting pending metadata signatures from Redis.

### Improvements

- **Delegated roles expiration**: Each delegated role now uses its own expiration configuration from Redis instead of a shared BINS_EXPIRATION setting.

### Testing

- **TUF unit test coverage**: Added unit tests for TUF metadata, metadata root, config, storage, signing, tasks, settings, delegations, artifacts, generate, bootstrap, delete, converter and utils. Storage mock is now global for tests.

### Security Fixes

- Fix: go-tuf affected by client DoS via malformed server response 
- Fix: go-tuf improperly validates the configured threshold for delegations
- Fix: sigstore legacy TUF client allows for arbitrary file writes with target cache path traversal 
- Fix: go-tuf Path Traversal in TAP 4 Multirepo Client Allows Arbitrary File Write via Malicious Repository Names 
- Upgraded github.com/theupdateframework/go-tuf/v2 to version v2.4.1

## v1.5.0

### Important Notes

- **⚠️ Pilot Version**: This release introduces a pilot/experimental TUF (The Update Framework) implementation. While the functionality is operational, it requires significant additional work and enhancements before production deployment. This version should be used for testing, evaluation, and gathering feedback.

### Features

- **TUF Bootstrap System**: Complete bootstrap functionality for initializing TUF repositories
  - Repository initialization with secure root key generation
  - Redis-based locking mechanism to prevent concurrent bootstrap operations
  - Real-time bootstrap status and lock monitoring
  - API endpoints: `GET /tuf/v1/bootstrap`, `POST /tuf/v1/bootstrap`

- **TUF Artifacts Management**: Publish and delete application artifacts in TUF repository
  - Automatic metadata generation for published artifacts
  - Automatic hash calculation (SHA256, SHA512) for artifact integrity verification
  - Separate TUF metadata per application
  - Conversion between application artifacts and TUF targets format
  - API endpoints: `POST /tuf/v1/artifacts/publish`, `POST /tuf/v1/artifacts/delete`

- **TUF Metadata Management**: Comprehensive metadata operations
  - Metadata rotation for root, targets, snapshot, and timestamp roles
  - Root keys rotation with offline signing support
  - Offline metadata signing capabilities
  - Trusted root metadata retrieval
  - Support for role-based access control with delegations
  - Configurable expiration and threshold per role
  - API endpoints: `POST /tuf/v1/metadata`, `GET /tuf/v1/metadata/sign`, `POST /tuf/v1/metadata/sign`, `GET /tuf/v1/metadata/root`

- **TUF Configuration Management**: Get and update TUF repository settings
  - Configurable expiration times, thresholds, and key counts for each metadata role
  - Redis-based configuration storage with per-admin, per-app isolation
  - API endpoints: `GET /tuf/v1/config`, `PUT /tuf/v1/config`

- **Task System**: Asynchronous task-based system for long-running operations
  - Real-time task status monitoring via Redis
  - Task states: PENDING, IN_PROGRESS, SUCCESS, ERRORED
  - API endpoint: `GET /tuf/v1/task`

- **Storage Enhancements**: Extended storage client capabilities
  - Added `DownloadObject` method to all storage clients (S3, GCS, MinIO)
  - Added `ListObjects` method for listing objects with prefix filtering
  - Unified storage interface across all providers

- **Database Integration**: Enhanced artifact model and TUF state tracking
  - Added `tuf_signed` field to artifacts
  - Added hash fields (SHA256, SHA512) to artifacts
  - Added `length` field to artifacts
  - TUF publish state tracking in MongoDB

### Maintenance

- Updated Go dependencies with TUF-related libraries (`go-tuf/v2`)
- Modular TUF architecture organized into separate packages (bootstrap, artifacts, metadata, config, tasks, signing, storage, delegations)
- All TUF endpoints require authentication and admin-only middleware
- Enhanced error handling and logging for TUF operations

## v1.4.6

### Security Fixes

- Fix: golang.org/x/crypto/ssh allows an attacker to cause unbounded memory consumption
- Fix: golang.org/x/crypto/ssh/agent vulnerable to panic if message is malformed due to out of bounds read
- Upgraded golang.org/x/crypto to version 0.45.0

## v1.4.5

### Features

- Changed `checkLatest` response: when the client app is newer than the published version, now returns a `possible_rollback` field with a URL to roll back.

- Add `tauri` updater.

## v1.4.4

### Features

- Change request types for channels, platforms, and architectures from form-data to application/json 

- Add `electron-builder` and `squirrel_darwin` updaters.

- Add `squirrel_windows` updater.

## v1.4.3

### Features

- **Storage Polymorphism**: Implemented polymorphic storage architecture for S3-compatible services
  - Added `StorageClient` interface for unified storage operations
  - Created factory pattern for dynamic storage client creation
  - Introduced base S3 client for common S3-compatible functionality

- **Cloud Provider Support**: Added support for multiple cloud storage providers
  - **DigitalOcean Spaces**: Full S3-compatible storage support with presigned URLs
  - **Google Cloud Storage**: Native GCS integration with service account authentication

- **Enhanced URL Parsing**: Improved URL parsing for different storage providers
  - Support for DigitalOcean Spaces URL format: `bucket-name.region.digitaloceanspaces.com/object-key`
  - Support for Google Cloud Storage URL format: `storage.googleapis.com/bucket-name/object-key`
  - Enhanced AWS S3 URL parsing for both virtual-hosted and legacy formats
  - Maintained MinIO URL parsing compatibility

### Configuration

- **Environment Variable Renaming**: Improved environment variable naming for better clarity and organization
  - Renamed `S3_BUCKET_NAME` to `S3_BUCKET_NAME_PRIVATE` for private bucket configuration
  - Renamed `S3_BUCKET_NAME_PUBLIC` to `S3_BUCKET_NAME` for public bucket configuration
  - Renamed `S3_ENDPOINT` to `S3_ENDPOINT_PRIVATE` for private bucket endpoint
  - Renamed `S3_ENDPOINT_PUBLIC` to `S3_ENDPOINT` for public bucket endpoint
  - Updated all configuration files and documentation to reflect the new naming convention

- Added new environment variables for cloud storage configuration:
  - `STORAGE_DRIVER`: Support extended to include `digitalocean`, and `gcp`.
  - `GCS_CREDENTIALS_FILE`: Path to Google Cloud service account credentials
  - `GCS_SERVICE_ACCOUNT_EMAIL`: GCS service account email for presigned URLs
  - `GCS_PRIVATE_KEY`: GCS private key for presigned URL generation

### Maintenance

- Updated Go dependencies to latest versions
- Enhanced error handling and logging across storage operations
- Improved code organization with dedicated storage package structure

## v1.4.2

### Bug Fixes

- Fixed an issue where the build name on S3 could be generated incorrectly.

### Features

- Updated the search app route; added sorting by channels, platforms, architectures, and published and critical status.

- Added intermediate required builds. More details here: https://ku9nov.github.io/faynoSync-site/docs/intermediate_build

- Added telemetry. More details here: https://ku9nov.github.io/faynoSync-site/docs/telemetry

### Maintenance

- New functions are covered by tests.


## v1.4.1

### Important Notes

- Team users update route using the id instead of the username.
- Optimize check permisiion logic. 
- Add update admin route.

### Potential bug fix

- Fix: golang.org/x/net vulnerable to Cross-site Scripting

## v1.4.0

### Features

- Enhanced the `DeleteDocument` function to check for related documents in the `apps` collection before deletion.
- Add `download` route.
- Add support for private S3 bucket.
- Add presigned URL support for MinIO and AWS.
- Add team based authorization matrix
- Add `whoami` route.

## v1.3.12

### Features

- Enhanced API Responses: Updated the return results for "Get All Apps" and "Search by Name" requests.

- Pagination Improvement: Introduced a limit for "Get Apps" requests to optimize performance.

- Add application logo support.

- Add application description.

- Add artifact deletion route.

## v1.3.11

### Potential bug fix

- Fix: jwt-go allows excessive memory allocation during header parsing
- Fix: HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net

## v1.3.10

### Potential bug fix

- Fix: Non-linear parsing of case-insensitive content in golang.org/x/net/html 
- Fix: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto


## v1.3.9

### Bug Fixes
- Fixed issue where MongoDB documents were sorted incorrectly by version string for the /apps/latest route.
- Fix MinIO URLs for correct working on localhost.
- Resolve the issue where the /checkVersion route returns an incorrect link because all artifacts have the same extension.


### Maintenance

- Added new mongoDB indexes for `apps` collection.

## v1.3.8

### Potential bug fix

- Fix: Bad documentation of error handling in `ParseWithClaims` can lead to potentially dangerous situations


## v1.3.7

### Features
- Added `binary` app support.
- Allowed `-` in platform name.
- Added `Slack` notifications.
- Added required parameter validation for `app_name` and `channel` in `FetchLatestVersionOfApp` endpoint. Returns an error if either parameter is missing.
- Added a database connection check to the health check.

### Bug Fixes

- Added validateParams to Update\Create app/channel/platform/arch
- Fixed an issue with `CheckLatestVersion` where cached metadata values persisted across calls, by moving `appMeta`, `channelMeta`, `platformMeta`, and `archMeta` to local variables.

## v1.3.6

### Important Notes

- **Important**: Fix "Authorization bypass in github.com/dgrijalva/jwt-go"
- **Important**: Now we can upload applications with the same extension, but this is only possible if the architectures are different.

### Bug Fixes

Fix: allow spaces in app name validation

### Features
- Added `browser extension` support.
- Implemented Performance Mode to optimize the `checkVersion` API request by caching responses in Redis.
- Added `link` encoding.
- Added `build number` to version. (0.0.1 => 0.0.1.137)
- Added new info API route which return links to latest build.

### Maintenance

- Multiple API routes were renamed.
- Added `semver` versions support.

## v1.3.5

### Important Notes
- **Important**: The authentication flow has changed to JWT.
- **Important**: The route for deleting a specific app by ID has been renamed to  `/apps/delete` from `/deleteApp`.
- **Important**: `/deleteApp` is now a new function.
- **Important**: The route for updating specific app by ID has been renamed to  `/apps/update` from `/update`.
- **Important**: `Archs, App names, Platform, channels` can be changed now.

### Features
- Added `Create, List, Delete` App functionality. It now works like `Platforms, Channels, Archs`.
- Added new tests.
- Added `UpdateApp, UpdateChannel, UpdatePlatform, UpdateArch` routes.

### Maintenance

- `Platforms`, `Channels`, `Archs` have been moved to the `apps_meta` collection. 

## v1.3.4

### Features
- Added `Changelog` to check latest version response.
- Added `Critical` parameter.

### Maintenance

- Refactored `List`, `Create`, `Delete` mongodb functions.

## v1.3.3

### Important Notes
- **Important**: The `POST` request uses body form-data instead of URL parameters.
Example:
```
--form 'data="{\"app_name\":\"app\",\"version\":\"0.0.2\",\"channel\":\"\",\"publish\":true,\"platform\":\"\",\"arch\":\"\"}"'
```

### Maintenance
- Updated Go modules.
- Refactored `createChannel`, `createPlatform`, and `createArch` functions.
- Refactored `deleteChannel`, `deletePlatform`, and `deleteArch` functions.
- All tests were updated for the new functionality.
### Features
- Added `Changelog` functionality to handle `upload` and `update` requests.
- Updated logging flow in the application.
- Refactored `ValidateParams` function for parsing the request body.

## v1.3.2

### Important Notes
- **Important**: Updated `Postman` template.

### Maintenance
- Added configurations for `one command` local development.
- Added `Dockerfile`
- Added `Minio` deployment to `docker compose`

### Features
- Add functionality to handle cases where the client app sends `platform` and `arch` parameters that do not exist. In such cases, the system should ignore the parameters and return the appropriate version.
    - If the client app sends either `platform` or `arch` parameters, and they exist in `faynoSync`, the system should return the closest matching version to the request. Any incorrect `platform` or `arch` names should result in appropriate error messages.
- Implemented a new API
    - SignUp
    - Update (App)
- Implemented new e2e test
    - TestSignUp
    - TestUpdate

## v1.3.1

### Important Notes

App is renamed to `faynoSync`.

- **Important**: `channel_name` parameter renamed to `channel`
- **Important**: Updated `Postman` template.
- **Important**: `checkVersion` changed from `POST` to `GET`
- **Important**: MongoDB architecture is changed to all in one collection. Changed mongoDB objects structure.

### Maintenance

- Added new `mongodb` migrations.
- Added `flutter` example app.

### Features

- :tada: Implemented the published feature. Now the API returns only published versions.
- Implement multiple files uploading.
- Updated `Postman` collection.
- Implemented a new APIs
    - Creating platforms
    - Removing platforms
    - List platforms
    - Creating architectures
    - Removing architectures
    - List architectures

- Implemented new e2e tests
    - TestPlatformCreate
    - TestUploadAppWithoutPlatform
    - TestArchCreate
    - TestUploadAppWithoutArch
    - TestDeletePlatform
    - TestDeleteArch
    - TestListArchs
    - TestListPlatforms
    - TestListChannels
    - TestListArchsWhenExist
    - TestListPlatformsWhenExist
    - TestListChannelsWhenExist
    Other tests is adapted.

### Bug Fixes

- Fixed a critical issue where returned versions were incorrectly compared when the version numbers were greater than 9 (e.g., 0.0.14).

## v1.2.0

### Important Notes

- **Important**: Changed the method of creating an admin user. Now, after creation, the web server starts and operates in normal mode, so it is recommended to use creation in complex with migration.

### Maintenance

- Added `MONGODB_URL_TESTS` to `.env.example`

### Docker
- Added `mongoDB` for testing to `docker compose` configuration.

### Features

- :tada: Implemented e2e tests
    - TestHealthCheck
    - TestLogin
    - TestUploadApp
    - TestUploadDuplicateApp (expected result from api "failed")
    - TestDeleteApp
    - TestChannelCreateNightly
    - TestChannelCreateStable
    - TestUploadAppWithoutChannel (expected result from api "failed")
    - TestMultipleUploadWithChannels
    - TestSearchApp
    - TestCheckVersionLatestVersion
    - TestMultipleDelete
    - TestDeleteNightlyChannel
    - TestDeleteStableChannel

## v1.1.0

### Important Notes

- **Important**: After first creating channel, field `channel_name` is required.

Added a set of functionalities for the operation and support of deployment channels.
Many checks have been added for a more accurate and expected behavior of the application.

### Features

- :tada: Implemented a new feature
    - Creating channels
    - Removing channels
    - List channels

## v1.0.0

### Important Notes

- **Important**: `Bearer` in the authorization header is now required.
- **Important**: Updated API reference and README.

### Maintenance

- Added initial functionality
    - `MongoDB` functionalitty
    - `MongoDB` migrations with indexing
    - `s3` support
    - `JavaScript` and `Python` usage examples
    - `Terraform` configuration for creating `s3` bucket
    - Added `Postman` collection example
    - Added `.env.example`


### Features

- :tada: Implemented a new features
    - Authentication (Auth)
    - Uploading
    - Removing
    - Check latest version feature
    - Searching

### Docker

- Added `docker-compose` file.

## v0.0.1 (Example)

### Important Notes

- **Important**: Removed something
- **Important**: Updated something
- App now requires something

### Maintenance

- Removed a redundant feature
- Added a new functionality
- Improved overall performance
    - Enhanced user interface responsiveness

### Features

- :tada: Implemented a new feature
    - This feature allows users to...
- Added a user profile customization option

### Bug Fixes

- Fixed a critical issue that caused...