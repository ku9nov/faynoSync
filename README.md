# SAU

This application is a simple auto updater service written in Golang. It allows you to upload your application to S3 and set the version number. The client application can then check the version number against the auto updater service API. If the auto updater service has a newer version, it will return a link to the updated service, and the client application will show an alert.

## Installation

To use this application, you will need to have Golang installed on your machine. You can install it from the official [website](https://golang.org/doc/install).

Once you have installed Golang, clone this repository to your local machine:

```
git clone https://github.com/ku9nov/SAU.git
```

## Configuration
To configure the `SAU`, you will need to set the following environment variables:
```
S3_ACCESS_KEY (Your AWS access key ID.)
S3_SECRET_KEY (Your AWS secret access key.)
S3_REGION (The AWS region in which your S3 bucket is located.)
S3_BUCKET_NAME (The name of your S3 bucket.)
PORT (The port on which the auto updater service will listen. Default: 9000)
MONGODB_URL=mongodb://root:MheCk6sSKB1m4xKNw5I@127.0.0.1/cb_sau_db?authSource=admin (see docker-compose file)
```

You can set these environment variables in a .env file in the root directory of the application. 

## Usage
To use the auto updater service, follow these steps:
1. Build the application:
```
go build -o sau sau.go
```

2. Start the auto updater service with migrations:
```
./sau --migration
```
Note: To rollback your migrations run:
```
./sau --migration --rollback
```
3. Create Administration user:
```
./sau --username=admin --password=password
```

4. Upload your application to S3 and set the version number in Admin Api.

5. In your client application, make a POST request to the auto updater service API, passing the current version number as a query parameter:
```
http://localhost:8080/checkVersion?app_name=myapp&version=4.1.5
```

The auto updater service will return a JSON response with the following structure:

```
{
    "update_available": false,
    "update_url": "https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.1.5.gz"
}
```

If an update is available, the update_available field will be true, and the update_url field will contain a link to the updated application.

6. In your client application, show an alert to the user indicating that an update is available and provide a link to download the updated application.

## License
This application is licensed under the Apache license. See the LICENSE file for more details