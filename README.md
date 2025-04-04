# FaynoSync

<div align="center">
  
  [![Documentation](https://img.shields.io/badge/Documentation-available-brightgreen)](https://ku9nov.github.io/faynoSync-site/docs/intro)
  ![Docker Pulls](https://img.shields.io/docker/pulls/ku9nov/faynosync)
  ![GitHub Release](https://img.shields.io/github/v/release/ku9nov/faynoSync)
  ![Docker Compose Test](https://github.com/ku9nov/faynoSync/actions/workflows/tests.yml/badge.svg)

</div>

This application is a simple API server for automatically updating client applications. It allows you to upload your application to S3 and set the version number. The client application can then check the version number against the auto updater service API. If the service has a newer version, it will return a link to the updated service, and the client application will show an alert.

The API server is designed for straightforward and intuitive application management. It supports updating client applications both in the background and on-demand, depending on how it's implemented in the client application. This provides flexibility in choosing the update method that best suits your needs.

## Documentation
The documentation is available in this repository [faynoSync-site](https://github.com/ku9nov/faynoSync-site) and at this link [faynoSync Documentation](https://ku9nov.github.io/faynoSync-site/docs/intro).

## Frontend
The repository with the available frontend is available in this repository [faynoSync-dashboard](https://github.com/ku9nov/faynoSync-dashboard).

###  Client Application Examples

You can find examples of client applications [here](https://github.com/ku9nov/faynoSync/tree/main/examples).

### API usage template

You can find the Postman template [here](https://github.com/ku9nov/faynoSync/blob/main/examples/faynoSync.postman_collection.json), or you can check available API requests [here](https://github.com/ku9nov/faynoSync/blob/main/API.md).


## Installation

To use this application, you will need to have Golang installed on your machine. You can install it from the official [website](https://golang.org/doc/install).

Once you have installed Golang, clone this repository to your local machine:

```
git clone https://github.com/ku9nov/faynoSync.git
```

## Configuration
To configure the `faynoSync`, you will need to set the following environment variables:
```
STORAGE_DRIVER (`minio` or `aws`)
S3_ACCESS_KEY (Your AWS or Minio access key ID.)
S3_SECRET_KEY (Your AWS or Minio secret access key.)
S3_REGION (The AWS region in which your S3 bucket is located. For Minio this value should be empty.)
S3_BUCKET_NAME (The name of your S3 bucket.)
S3_ENDPOINT (s3 endpoint, check documentation of your cloud provider)
ALLOWED_CORS ( urls to allow CORS configuration)
PORT (The port on which the auto updater service will listen. Default: 9000)
MONGODB_URL=mongodb://root:MheCk6sSKB1m4xKNw5I@127.0.0.1/cb_faynosync_db?authSource=admin (see docker-compose file)
API_KEY (generated by 'openssl rand -base64 16') Used for SignUp
API_URL=(public URL to this API)
PERFORMANCE_MODE (Set to `true` to enable performance mode)
REDIS_HOST (The hostname for the Redis server, default: `localhost`)
REDIS_PORT (The port for the Redis server, default: `6379`)
REDIS_PASSWORD (Password for Redis, leave empty if not set)
REDIS_DB (The Redis database number to use, default: `0`)
```

You can set these environment variables in a `.env` file in the root directory of the application. You can use the `.env.local` file, which contains all filled variables.

### Docker configuration
To build and run the API with all dependencies, you can use the following command:
```
docker-compose up --build
```
You can now run tests using this command (please wait until the `s3-service` successfully creates the bucket):
```
docker exec -it faynoSync_backend "/usr/bin/faynoSync_tests"
```
If you only want to run dependency services (for local development without Docker), use this command:
```
docker-compose -f docker-compose.yaml -f docker-compose.development.yaml up
```
## Usage
To use the auto updater service, follow these steps:
1. Build the application:
```
go build -o faynoSync faynoSync.go
```

2. Start the auto updater service with migrations:
```
./faynoSync --migration
```
Note: To rollback your migrations run:
```
./faynoSync --migration --rollback
```

3. Upload your application to S3 and set the version number in [faynoSync-dashboard](https://github.com/ku9nov/faynoSync-dashboard) or using API.

4. In your client application, make a GET request to the auto updater service API, passing the current version number as a query parameter:
```
http://localhost:9000/checkVersion?app_name=myapp&version=0.0.1
```

The auto updater service will return a JSON response with the following structure:

```
{
    "update_available": false,
    "update_url_deb": "http://localhost:9000/download?key=secondapp/myapp-0.0.1.deb",
    "update_url_rpm": "http://localhost:9000/download?key=secondapp/myapp-0.0.1.rpm"
}
```

If an update is available, the update_available field will be true, and the update_url field will contain a link to the updated application.

5. In your client application, show an alert to the user indicating that an update is available and provide a link to download the updated application.

## Testing
Run e2e tests:
```
go test
```
Build test binary file:
```
go test -c -o faynoSync_tests
```
**Test Descriptions**

To successfully run the tests and have them pass, you need to populate the .env file.

The tests verify the implemented API using a test database and an existing S3 bucket.

**List of Tests**

    - TestHealthCheck
    - TestLogin
    - TestFailedLogin (expected result from API "401")
    - TestListApps
    - TestListAppsWithInvalidToken (expected result from API "401")
    - TestAppCreate
    - TestSecondaryAppCreate (expected result from API "failed")
    - TestUploadApp
    - TestUploadDuplicateApp (expected result from API "failed")
    - TestDeleteApp
    - TestChannelCreateNightly
    - TestChannelCreateStable
    - TestUploadAppWithoutChannel (expected result from API "failed")
    - TestMultipleUploadWithChannels
    - TestSearchApp
    - TestCheckVersionLatestVersion
    - TestFetchkLatestVersionOfApp
    - TestMultipleDelete
    - TestDeleteNightlyChannel
    - TestDeleteStableChannel
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
    - TestSignUp
    - TestFailedSignUp (expected result from API "401")
    - TestUpdateSpecificApp
    - TestListAppsWhenExist
    - TestDeleteAppMeta
    - TestUpdateChannel
    - TestUpdateApp
    - TestUpdatePlatform
    - TestUpdateArch
    - TestFailedUpdatePlatform (expected result from API "400")
    - TestChannelCreateWithWrongName (expected result from API "400")
    - TestCreateSecondPlatform
    - TestCreateSecondArch
    - TestMultipleUploadWithSameExtension
    - TestCheckVersionWithSameExtensionArtifactsAndDiffPlatformsArchs
    - TestMultipleDeleteWithSameExtensionArtifactsAndDiffPlatformsArchs
    - TestDeleteSecondPlatform
    - TestDeleteSecondArch
    
## Create new migrations
Install migrate tool [here](https://github.com/golang-migrate/migrate/blob/master/cmd/migrate/README.md).
```
cd mongod/migrations
migrate create -ext json name_of_migration
```
Then run the migrations again.
## License
This application is licensed under the Apache license. See the LICENSE file for more details
