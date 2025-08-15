# Changelog

## v1.4.4

### Features

- Change request types for channels, platforms, and architectures from form-data to application/json 

- Add `electron-builder` and `squirrel_darwin` updaters.

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