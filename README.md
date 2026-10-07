# FaynoSync

![a-github-banner-for-faynosync-featuring](https://github.com/user-attachments/assets/219a2028-3cd2-4a8e-9e55-16b1c40c55ca)

<div align="center">
  
  [![Documentation](https://img.shields.io/badge/Documentation-available-brightgreen)](https://faynosync.com/docs/intro)
  ![Docker Pulls](https://img.shields.io/docker/pulls/ku9nov/faynosync)
  ![GitHub Release](https://img.shields.io/github/v/release/ku9nov/faynoSync)
  ![Docker Compose Test](https://github.com/ku9nov/faynoSync/actions/workflows/tests.yml/badge.svg)

</div>

---

**Self-hosted update server for desktop apps — your release pipeline, fully under your control.**

### ⚡ Quickstart (<5 min)

Spin up the API with MongoDB, Redis, and a preconfigured S3-compatible storage (Garage) — no cloud account required:

```bash
git clone https://github.com/ku9nov/faynoSync.git
cd faynoSync
docker compose up --build                                   # API + MongoDB + Redis + Garage + Dashboard
docker compose exec -T backend /usr/bin/faynoSync migrate up # run after the stack is healthy
```

The API is now live at `http://localhost:9000`. Check for an update from any client:

```bash
curl "http://localhost:9000/checkVersion?app_name=myapp&version=0.0.1&owner=admin"
```

Upload builds and manage versions via the dashboard served by the API at `http://localhost:9000/dashboard/` or the [REST API](https://faynosync.com/docs/api). Full setup, env vars, and self-build instructions are below.

---

## 📖 Overview

faynoSync is a self-hosted, open-source API server for managing and updating cross-platform desktop applications (Windows, macOS, Linux).
It enables automatic and on-demand updates for client software, making it easy to deliver new versions to users through a customizable update workflow.

The server allows developers to upload application builds to S3, set version metadata, and expose a simple REST API for clients to check for updates.
When a client queries the API, it receives version information and a download URL if an update is available.

faynoSync supports both background updates and manual update prompts, depending on how the client integrates with the API. This gives developers full control over how and when updates are delivered to end-users.

It’s ideal for managing updates in Electron apps, native desktop applications, or any cross-platform software where you want full control over versioning, distribution, and update channels (e.g. stable, beta, nightly).

![demo](https://github.com/user-attachments/assets/7071cfb6-8293-4069-a0c1-b8fda70d431f)

---

## 🛠️ Supported Technologies

| Category | Technology | Description |
|----------|------------|-------------|
| **API Framework** | Go (Golang) | Main application server built with Go |
| **Database** | MongoDB | Primary database for storing application metadata, users, and configurations |
| **Cache & Performance** | Redis | Required. Caching, statistics, TUF task state, rate limits |
| **Updaters** | electron-builder | Update feeds for Electron apps (auto-generated `latest*.yml` / `latest-mac.yml`) |
| | Tauri | Updater for Tauri apps (signature-based verification) |
| | Squirrel | Update support for Squirrel.Windows and Squirrel.Mac |
| | Velopack | Cross-platform installer/updater framework |
| | Sparkle | macOS-only installer/updater framework |
| | Manual | Direct download without a framework-specific update feed |
| **Storage** | S3-Compatible | Supports multiple cloud storage providers: |
| | AWS S3 | Amazon Web Services Simple Storage Service |
| | Garage | Recommended local S3-compatible storage, used via the AWS SDK |
| | MinIO | Deprecated local S3-compatible storage option that still works but is no longer maintained |
| | Google Cloud Storage | Google Cloud Platform storage service |
| | DigitalOcean Spaces | DigitalOcean's S3-compatible object storage |

---

### 📖 Documentation Links
- **Repository**: [faynoSync-site](https://github.com/ku9nov/faynoSync-site) - Source code for documentation
- **Live Documentation**: [faynoSync Documentation](https://faynosync.com/docs/intro) - Online documentation

---

### 🖥️ Dashboard
- The web dashboard lives in [`dashboard/`](dashboard) and is embedded into the API binary, which serves it at `/dashboard/`. Set `DASHBOARD_ENABLED=false` to turn it off.

---

## 📱 Client Application Examples

You can find examples of client applications [here](https://github.com/ku9nov/faynoSync/tree/main/examples).

### 🔗 Example Links
- **Examples Directory**: [Client Application Examples](https://github.com/ku9nov/faynoSync/tree/main/examples) - Various client implementations

### 📋 API Usage Template

- **Postman Collection**: [faynoSync.postman_collection.json](https://github.com/ku9nov/faynoSync/blob/main/examples/faynoSync.postman_collection.json) - Ready-to-use API requests
- **API Documentation**: [API Reference](https://faynosync.com/docs/api) - Complete API reference

---

## 🚀 Installation

To build this application from source, you will need Go and, for the embedded dashboard, Node.js with Yarn. Install Go from the official [website](https://golang.org/doc/install).

### 📥 Installation Steps

1. **Install Go**: Download and install from [golang.org](https://golang.org/doc/install)

2. **Clone Repository**: Once you have installed Golang, clone this repository to your local machine:

```bash
git clone https://github.com/ku9nov/faynoSync.git
```

---

## ⚙️ Configuration

All settings are environment variables. [`.env.example`](.env.example) lists every variable with a one-line description and working values for local development; the full reference is the [Environment Variables Overview](https://faynosync.com/docs/getting-started/env-overview).

- Running the API from source: `cp .env.example .env`. The API reads `.env` from its working directory, and environment variables take precedence.
- Docker Compose reads `.env.example` directly and overrides only the service hostnames (see the `backend` service in `docker-compose.yaml`).

### 🧪 Local Storage (Garage)

For local development the recommended storage is Garage with the `aws` storage driver: Garage is the S3-compatible backend, and uploads and downloads go through the AWS SDK. The Docker Compose setup creates the buckets and imports the credentials from `.env.example` automatically.

Garage admin UI is available at `http://localhost:3909/` (user: `admin`, password: `BjjctVsoSg4FKkT81VKt18`).

The dashboard is available at `http://localhost:9000/dashboard/`. For hot reload while working on it, run `yarn dev` in `dashboard/`: it serves on `http://localhost:3000/dashboard/` and proxies API requests to `http://localhost:9000`. Run `yarn build` there before `go build` to embed it into a binary you build yourself.

---

## 🐳 Docker Configuration

To build and run the API with all dependencies ([Local Setup — Docker Compose](https://faynosync.com/docs/getting-started/local-deploy?local-setup=compose)), use the following command:

```bash
docker compose up --build
```

### 📦 Running Migrations

You can run migrations using this command after `docker compose up --build` finishes:

```bash
docker compose exec -T backend /usr/bin/faynoSync migrate up
```

### 🧪 Running Tests

You can now run tests using this command after `docker compose up --build` finishes and the storage service becomes healthy:

```bash
docker exec -it faynoSync_backend "/usr/bin/faynoSync_tests"
```

### 🔧 Development Setup

If you only want to run dependency services (for local development without Docker), use this command:

```bash
docker compose up -d db cache s3 webui
```

Naming the services starts only them (and their dependencies), so `backend` stays down and you can run the API and dashboard from source while MongoDB, Redis, and Garage stay containerized. `docker compose down` stops them as usual. Step-by-step guide: [Local Setup — from source](https://faynosync.com/docs/getting-started/local-deploy?local-setup=source).

---

## 💻 Usage

To use the auto updater service, follow these steps:

### 🔨 Build the Application

```bash
cd dashboard && yarn install && yarn build && cd ..
go build -o faynoSync .
```

Skipping the dashboard build still produces a working API, but `/dashboard/` returns `503`.

### 🚀 Start the Service

1. **Start API Server**:
```bash
./faynoSync
```

2. **Run Migrations** (after API health check):
```bash
./faynoSync migrate up
```

3. **Rollback Migrations** (if needed):
```bash
./faynoSync migrate down
```

### 📤 Upload Your Application

3. Upload your application to S3 and set the version number in the dashboard (`/dashboard/`) or using API.
   For large builds, skip the reverse proxy and upload straight to storage with presigned URLs: `POST /upload/init` → `PUT` → `POST /upload/complete`, see [Presigned Uploads](https://faynosync.com/docs/presigned-uploads).

### 🔍 Check for Updates

4. In your client application, make a GET request to the auto updater service API, passing the current version number as a query parameter:

```
http://localhost:9000/checkVersion?app_name=myapp&version=0.0.1&owner=admin
```

### 📋 API Response

The auto updater service will return a JSON response with the following structure:

```json
{
    "update_available": true,
    "update_url_deb": "https://<bucket_name>.s3.amazonaws.com/myapp-admin/stable/linux/amd64/myapp-0.0.2.deb",
    "update_url_rpm": "https://<bucket_name>.s3.amazonaws.com/myapp-admin/stable/linux/amd64/myapp-0.0.2.rpm",
    "changelog": "### Changelog\n\n- Added new feature X",
    "critical": false
}
```

Each artifact is returned as `update_url_<ext>` (`update_url_dmg`, `update_url_deb`, ...), or as `update_url` when the file has no extension. Response formats for every updater are in [Check Latest Version](https://faynosync.com/docs/api/info/latest).

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

### 🧪 Run Unit Tests

```bash
# Optional: set MONGODB_URL_TESTS for tests that require a MongoDB connection
# export MONGODB_URL_TESTS=mongodb://root:MheCk6sSKB1m4xKNw5I@localhost/cb_faynosync_db_tests?authSource=admin
go test ./server/... -race
```

### 📋 Test Requirements

**Test Descriptions**

To successfully run the tests and have them pass, create the `.env` file from `.env.example`.

The tests verify the implemented API using a test database and an existing S3 bucket.

---

## 🔄 Database Migrations

### 📦 Install Migration Tool

Install migrate tool [here](https://github.com/golang-migrate/migrate/blob/master/cmd/migrate/README.md).

### 🆕 Create New Migrations

```bash
cd mongod/migrations
migrate create -ext json name_of_migration
```

Then run migrations with the built-in command:

```bash
./faynoSync migrate up
```

### 🔗 Migration Tool Link
- **Migration Tool**: [golang-migrate](https://github.com/golang-migrate/migrate/blob/master/cmd/migrate/README.md) - Database migration utility

---
