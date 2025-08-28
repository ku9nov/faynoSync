# FaynoSync

![a-github-banner-for-faynosync-featuring](https://github.com/user-attachments/assets/219a2028-3cd2-4a8e-9e55-16b1c40c55ca)

<div align="center">
  
  [![Documentation](https://img.shields.io/badge/Documentation-available-brightgreen)](https://ku9nov.github.io/faynoSync-site/docs/intro)
  ![Docker Pulls](https://img.shields.io/docker/pulls/ku9nov/faynosync)
  ![GitHub Release](https://img.shields.io/github/v/release/ku9nov/faynoSync)
  ![Docker Compose Test](https://github.com/ku9nov/faynoSync/actions/workflows/tests.yml/badge.svg)

</div>

---

## 📖 Overview

faynoSync is a self-hosted, open-source API server for managing and updating cross-platform desktop applications (Windows, macOS, Linux).
It enables automatic and on-demand updates for client software, making it easy to deliver new versions to users through a customizable update workflow.

The server allows developers to upload application builds to S3, set version metadata, and expose a simple REST API for clients to check for updates.
When a client queries the API, it receives version information and a download URL if an update is available.

faynoSync supports both background updates and manual update prompts, depending on how the client integrates with the API. This gives developers full control over how and when updates are delivered to end-users.

It’s ideal for managing updates in Electron apps, native desktop applications, or any cross-platform software where you want full control over versioning, distribution, and update channels (e.g. stable, beta, nightly).

---

## 🛠️ Supported Technologies

| Category | Technology | Description |
|----------|------------|-------------|
| **API Framework** | Go (Golang) | Main application server built with Go |
| **Database** | MongoDB | Primary database for storing application metadata, users, and configurations |
| **Cache & Performance** | Redis | Used for performance mode and statistics caching |
| **Storage** | S3-Compatible | Supports multiple cloud storage providers: |
| | AWS S3 | Amazon Web Services Simple Storage Service |
| | MinIO | Self-hosted S3-compatible object storage |
| | Google Cloud Storage | Google Cloud Platform storage service |
| | DigitalOcean Spaces | DigitalOcean's S3-compatible object storage |

---

### 📖 Documentation Links
- **Repository**: [faynoSync-site](https://github.com/ku9nov/faynoSync-site) - Source code for documentation
- **Live Documentation**: [faynoSync Documentation](https://ku9nov.github.io/faynoSync-site/docs/intro) - Online documentation

---

### 🖥️ Frontend Links
- **Dashboard Repository**: [faynoSync-dashboard](https://github.com/ku9nov/faynoSync-dashboard) - Web-based management interface

---

## 📱 Client Application Examples

You can find examples of client applications [here](https://github.com/ku9nov/faynoSync/tree/main/examples).

### 🔗 Example Links
- **Examples Directory**: [Client Application Examples](https://github.com/ku9nov/faynoSync/tree/main/examples) - Various client implementations

### 📋 API Usage Template

- **Postman Collection**: [faynoSync.postman_collection.json](https://github.com/ku9nov/faynoSync/blob/main/examples/faynoSync.postman_collection.json) - Ready-to-use API requests
- **API Documentation**: [API.md](https://github.com/ku9nov/faynoSync/blob/main/API.md) - Complete API reference

---

## 🚀 Installation

To use this application, you will need to have Golang installed on your machine. You can install it from the official [website](https://golang.org/doc/install).

### 📥 Installation Steps

1. **Install Go**: Download and install from [golang.org](https://golang.org/doc/install)

2. **Clone Repository**: Once you have installed Golang, clone this repository to your local machine:

```bash
git clone https://github.com/ku9nov/faynoSync.git
```

---

## ⚙️ Configuration

To configure the `faynoSync`, you will need to set the following environment variables:

### 🔧 Required Environment Variables

```bash
# Storage Configuration
STORAGE_DRIVER (`minio`, `aws`, `gcp` or `digitalocean`)
S3_ACCESS_KEY (Your AWS or Minio access key ID.)
S3_SECRET_KEY (Your AWS or Minio secret access key.)
S3_REGION (The AWS region in which your S3 bucket is located. For Minio this value should be empty.)
S3_BUCKET_NAME_PRIVATE (The name of your private S3 bucket.)
S3_ENDPOINT_PRIVATE (s3 endpoint, check documentation of your cloud provider)
S3_BUCKET_NAME (The name of your public S3 bucket. Artifacts will be uploaded here by default.)
S3_ENDPOINT (The public bucket endpoint for S3. Check the documentation of your cloud provider. Artifacts will be uploaded here by default.)

# Server Configuration
ALLOWED_CORS (urls to allow CORS configuration)
PORT (The port on which the auto updater service will listen. Default: 9000)

# Database Configuration
MONGODB_URL=mongodb://root:MheCk6sSKB1m4xKNw5I@127.0.0.1/cb_faynosync_db?authSource=admin (see docker-compose file)

# Security Configuration
API_KEY (generated by 'openssl rand -base64 16') Used for SignUp
API_URL=(public URL to this API)

# Performance Configuration
PERFORMANCE_MODE (Set to `true` to enable performance mode)

# Redis Configuration
REDIS_HOST (The hostname for the Redis server, default: `localhost`)
REDIS_PORT (The port for the Redis server, default: `6379`)
REDIS_PASSWORD (Password for Redis, leave empty if not set)
REDIS_DB (The Redis database number to use, default: `0`)

# Feature Flags
ENABLE_PRIVATE_APP_DOWNLOADING=false (if enabled, then apps located in private S3 can be downloaded using the public API; if disabled, then download links require authentication)
ENABLE_TELEMETRY (Set to `true` to enable telemetry)
```

### 📝 Environment File Setup

You can set these environment variables in a `.env` file in the root directory of the application. You can use the `.env.local` file, which contains all filled variables.

---

## 🐳 Docker Configuration

To build and run the API with all dependencies, you can use the following command:

```bash
docker-compose up --build
```

### 🧪 Running Tests

You can now run tests using this command (please wait until the `s3-service` successfully creates the bucket):

```bash
docker exec -it faynoSync_backend "/usr/bin/faynoSync_tests"
```

### 🔧 Development Setup

If you only want to run dependency services (for local development without Docker), use this command:

```bash
docker-compose -f docker-compose.yaml -f docker-compose.development.yaml up
```

---

## 💻 Usage

To use the auto updater service, follow these steps:

### 🔨 Build the Application

```bash
go build -o faynoSync faynoSync.go
```

### 🚀 Start the Service

1. **Start with Migrations**:
```bash
./faynoSync --migration
```

2. **Rollback Migrations** (if needed):
```bash
./faynoSync --migration --rollback
```

### 📤 Upload Your Application

3. Upload your application to S3 and set the version number in [faynoSync-dashboard](https://github.com/ku9nov/faynoSync-dashboard) or using API.

### 🔍 Check for Updates

4. In your client application, make a GET request to the auto updater service API, passing the current version number as a query parameter:

```
http://localhost:9000/checkVersion?app_name=myapp&version=0.0.1&owner=admin
```

### 📋 API Response

The auto updater service will return a JSON response with the following structure:

```json
{
    "update_available": false,
    "update_url_deb": "http://localhost:9000/download?key=secondapp/myapp-0.0.1.deb",
    "update_url_rpm": "http://localhost:9000/download?key=secondapp/myapp-0.0.1.rpm"
}
```

If an update is available, the `update_available` field will be `true`, and the `update_url` field will contain a link to the updated application.

### 🔔 User Notification

5. In your client application, show an alert to the user indicating that an update is available and provide a link to download the updated application.

---

## 🧪 Testing

### 🚀 Run End-to-End Tests

```bash
go test
```

### 🔨 Build Test Binary

```bash
go test -c -o faynoSync_tests
```

### 📋 Test Requirements

**Test Descriptions**

To successfully run the tests and have them pass, you need to populate the `.env` file.

The tests verify the implemented API using a test database and an existing S3 bucket.

<details>
<summary><strong>📋 Complete List of Tests</strong></summary>

<br>

  <li>TestHealthCheck</li>
  <li>TestLogin</li>
  <li>TestFailedLogin (expected result from API "401")</li>
  <li>TestListApps</li>
  <li>TestListAppsWithInvalidToken (expected result from API "401")</li>
  <li>TestAppCreate</li>
  <li>TestSecondaryAppCreate (expected result from API "failed")</li>
  <li>TestUploadApp</li>
  <li>TestUploadDuplicateApp (expected result from API "failed")</li>
  <li>TestDeleteApp</li>
  <li>TestChannelCreateNightly</li>
  <li>TestChannelCreateStable</li>
  <li>TestUploadAppWithoutChannel (expected result from API "failed")</li>
  <li>TestMultipleUploadWithChannels</li>
  <li>TestSearchApp</li>
  <li>TestCheckVersionLatestVersion</li>
  <li>TestFetchkLatestVersionOfApp</li>
  <li>TestMultipleDelete</li>
  <li>TestDeleteNightlyChannel</li>
  <li>TestDeleteStableChannel</li>
  <li>TestPlatformCreate</li>
  <li>TestUploadAppWithoutPlatform</li>
  <li>TestArchCreate</li>
  <li>TestUploadAppWithoutArch</li>
  <li>TestDeletePlatform</li>
  <li>TestDeleteArch</li>
  <li>TestListArchs</li>
  <li>TestListPlatforms</li>
  <li>TestListChannels</li>
  <li>TestListArchsWhenExist</li>
  <li>TestListPlatformsWhenExist</li>
  <li>TestListChannelsWhenExist</li>
  <li>TestSignUp</li>
  <li>TestFailedSignUp (expected result from API "401")</li>
  <li>TestUpdateSpecificApp</li>
  <li>TestListAppsWhenExist</li>
  <li>TestDeleteAppMeta</li>
  <li>TestUpdateChannel</li>
  <li>TestUpdateApp</li>
  <li>TestUpdatePlatform</li>
  <li>TestUpdateArch</li>
  <li>TestFailedUpdatePlatform (expected result from API "400")</li>
  <li>TestChannelCreateWithWrongName (expected result from API "400")</li>
  <li>TestCreateSecondPlatform</li>
  <li>TestCreateSecondArch</li>
  <li>TestMultipleUploadWithSameExtension</li>
  <li>TestCheckVersionWithSameExtensionArtifactsAndDiffPlatformsArchs</li>
  <li>TestMultipleDeleteWithSameExtensionArtifactsAndDiffPlatformsArchs</li>
  <li>TestDeleteSecondPlatform</li>
  <li>TestDeleteSecondArch</li>
  <li>TestCreatePublicApp</li>
  <li>TestDeletePublicAppMeta</li>
  <li>TestUpdateSpecificAppWithSecondUser (expected result from API "500")</li>
  <li>TestListAppsWithSecondUser</li>
  <li>TestListChannelsWithSecondUser</li>
  <li>TestListPlatformsWithSecondUser</li>
  <li>TestListArchsWithSecondUser</li>
  <li>TestUpdateAppWithSecondUser (expected result from API "500")</li>
  <li>TestUpdateChannelWithSecondUser (expected result from API "500")</li>
  <li>TestUpdatePlatformWithSecondUser (expected result from API "500")</li>
  <li>TestUpdateArchWithSecondUser (expected result from API "500")</li>
  <li>TestMultipleDeleteWithSameExtensionArtifactsAndDiffPlatformsArchsWithSecondUser (expected result from API "500")</li>
  <li>TestDeleteNightlyChannelWithSecondUser (expected result from API "500")</li>
  <li>TestDeletePlatformWithSecondUser (expected result from API "500")</li>
  <li>TestDeleteArchWithSecondUser (expected result from API "500")</li>
  <li>TestDeleteAppMetaWithSecondUser (expected result from API "500")</li>
  <li>TestCreateTeamUser</li>
  <li>TestTeamUserLogin</li>
  <li>TestFailedUploadAppUsingTeamUser (expected result from API "403")</li>
  <li>TestFailedUpdateAppUsingTeamUser (expected result from API "403")</li>
  <li>TestFailedUpdateChannelUsingTeamUser (expected result from API "403")</li>
  <li>TestFailedUpdatePlatformUsingTeamUser (expected result from API "403")</li>
  <li>TestFailedUpdateArchUsingTeamUser (expected result from API "403")</li>
  <li>TestListAppsUsingTeamUserBeforeCreate</li>
  <li>TestListChannelsUsingTeamUserBeforeCreate</li>
  <li>TestListPlatformsUsingTeamUserBeforeCreate</li>
  <li>TestListArchsUsingTeamUserBeforeCreate</li>
  <li>TestAppCreateTeamUser</li>
  <li>TestListAppsUsingTeamUser</li>
  <li>TestFailedDeleteTeamUserApp (expected result from API "403")</li>
  <li>TestChannelCreateTeamUser</li>
  <li>TestListChannelsUsingTeamUser</li>
  <li>TestFailedDeleteTeamUserChannel (expected result from API "403")</li>
  <li>TestPlatformCreateTeamUser</li>
  <li>TestListPlatformsUsingTeamUser</li>
  <li>TestFailedDeleteTeamUserPlatform (expected result from API "403")</li>
  <li>TestArchCreateTeamUser</li>
  <li>TestListArchsUsingTeamUser</li>
  <li>TestFailedDeleteTeamUserArch (expected result from API "403")</li>
  <li>TestFailedUpdateTeamUser (expected result from API "403")</li>
  <li>TestUpdateTeamUser</li>
  <li>TestUpdateAppUsingTeamUser</li>
  <li>TestUpdateChannelUsingTeamUser</li>
  <li>TestUpdatePlatformUsingTeamUser</li>
  <li>TestUpdateArchUsingTeamUser</li>
  <li>TestFailedAppCreateTeamUser (expected result from API "403")</li>
  <li>TestDeleteTeamUserApp</li>
  <li>TestDeleteTeamUserChannel</li>
  <li>TestDeleteTeamUserPlatform</li>
  <li>TestDeleteTeamUserArch</li>
  <li>TestListTeamUsers</li>
  <li>TestDeleteTeamUser</li>
  <li>TestWhoAmIAdmin</li>
  <li>TestWhoAmITeamUser</li>
  <li>TestFailedUpdateAdminUser</li>
  <li>TestUpdateAdminUser</li>
  <li>TestFailedLoginWithOldPassword</li>
  <li>TestSuccessfulLoginWithNewPassword</li>
  <li>TestFailedUpdateAdminUserUsingTeamUser</li>
  <li>TestFilterSearchWithChannel</li>
  <li>TestFilterSearchWithChannelAndPublished</li>
  <li>TestFilterSearchWithChannelAndPublishedAndCritical</li>
  <li>TestFilterSearchWithChannelAndPublishedAndCriticalAndPlatform</li>
  <li>TestFilterSearchWithChannelAndPublishedAndCriticalAndPlatformAndArch</li>
  <li>TestSearchOnlyPublished</li>
  <li>TestSearchOnlyCritical</li>
  <li>TestSearchOnlyUniversalPlatform</li>
  <li>TestMultipleUploadWithIntermediate</li>
  <li>TestUpdateSpecificAppWithIntermediate</li>
  <li>TestCheckVersionWithIntermediate</li>
  <li>TestMultipleDeleteWithIntermediate</li>
  <li>TestTelemetryWithVariousParams</li>
  <li>TestCreateAppWithUpdaters</li>
  <li>TestPlatformCreateWindows</li>
  <li>TestUpdatePlatformWindows</li>
  <li>TestPlatformCreateMacos</li>
  <li>TestUpdatePlatformMacos</li>
  <li>TestPlatformCreateMacosSquirrel</li>
  <li>TestUpdatePlatformMacosSquirrel</li>
  <li>TestMultipleUploadWithUpdaters</li>
  <li>TestCheckVersionWithUpdaters</li>
  <li>TestSquirrelReleases (Not implemented yet)</li>
  <li>TestDeletePlatformWindows</li>
  <li>TestDeletePlatformMacos</li>
  <li>TestDeletePlatformMacosSquirrel</li>
  <li>TestDeleteAppMetaUpdaters</li>

</details>

---

## 🔄 Database Migrations

### 📦 Install Migration Tool

Install migrate tool [here](https://github.com/golang-migrate/migrate/blob/master/cmd/migrate/README.md).

### 🆕 Create New Migrations

```bash
cd mongod/migrations
migrate create -ext json name_of_migration
```

Then run the migrations again.

### 🔗 Migration Tool Link
- **Migration Tool**: [golang-migrate](https://github.com/golang-migrate/migrate/blob/master/cmd/migrate/README.md) - Database migration utility

---

## 📄 License

This application is licensed under the Apache license. See the LICENSE file for more details.

### 🔗 License Link
- **License File**: [LICENSE](LICENSE) - Apache License 2.0
