# API Reference

You can find `Postman` collection [here](examples/faynoSync.postman_collection.json).

### Check Health Status
Check the health status of the application.

Request:
```
curl -X GET http://localhost:9000/health
```

Response:

```
{
    "status": "healthy"
}
```

### SignUp
Authenticate and receive a token for accessing the API.

`POST /signup`

Request:
```
curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "password", "api_key": "UHp3aKb40fwpoKZluZByWQ"}' http://localhost:9000/signup
```

Response:

```
{
    "result": "Successfully created admin user."
}
```

### Login to App
Authenticate and receive a jwt token for accessing the API.

`POST /login`

Request:
```
curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}' http://localhost:9000/login
```

Response:

```
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"}
```

### Create app

Create app.

`POST /app/create`

Optional with `description`, `logo`, `private`. 

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body
**file**: logo of the app.

###### Body form data
**app**: Name of the app.

**description**: App description.

**private**: Lock app. (If selected, the app will be stored in a private bucket)

###### Request:
```
curl --location 'http://localhost:9000/app/create' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"app\":\"myapp\", \"description\": \"description of app\"}"' \
--form 'file=@"path_to_logo.png"'
```

###### Response:

```
{
   "createAppResult.Created":"641459ffb8760d74164e7e3c"
}
```

### Create channel (Optional)

:warning: After first creating, field `channel` is required.

Create deployment channel.

`POST /channel/create`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body form data
**channel**: Name of the channel.

###### Request:
```
curl --location 'http://localhost:9000/channel/create' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"channel\":\"nightly\"}"'
```

###### Response:

```
{
   "createChannelResult.Created":"641459ffb8360d74164e7e3c"
}
```

### Create platform (Optional)

:warning: After first creating, field `platform` is required.

Create deployment platform.

`POST /platform/create`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body form data
**platform**: Name of the platform.

###### Request:
```
curl --location 'http://localhost:9000/platform/create' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"platform\":\"linux\"}"'
```

###### Response:

```
{
   "createPlatformResult.Created":"641459ffb8360d74164e7e3c"
}
```

### Create arch (Optional)

:warning: After first creating, field `arch` is required.

Create deployment architecture.

`POST /arch/create`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body form data
**arch**: Arch of the app.

###### Request:
```
curl --location 'http://localhost:9000/arch/create' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"arch\":\"amd64\"}"'
```

###### Response:

```
{
   "createArchResult.Created":"641459ffb8360d74164e7e3c"
}
```

### List Apps

Retrieve a list of all apps.

`GET /app/list`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Request:
```
curl -X GET http://localhost:9000/app/list -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"
```

###### Response:

```
{
    "apps": [
        {
            "ID": "66ae18a29807f0696d967176",
            "AppName": "first",
            "Logo": "",
            "Updated_at": "2024-08-03T14:46:42.361+03:00"
        },
        {
            "ID": "66ae14024b663c058367f895",
            "AppName": "myapp",
            "Logo": "",
            "Updated_at": "2024-08-03T14:26:58.701+03:00"
        }
    ]
}
```

### Get All Channels

Retrieve a list of all channels.

`GET /channel/list`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Request:
```
curl -X GET http://localhost:9000/channel/list -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"
```

###### Response:

```
{
   "channels":[
      {
         "ID":"641459ffb8360d74164e7e3c",
         "ChannelName":"nightly",
         "Updated_at":"2023-03-17T14:15:59.818+02:00"
      },
      {
         "ID":"64145ebaedd163d59d52e1dc",
         "ChannelName":"stable",
         "Updated_at":"2023-03-17T14:36:10.278+02:00"
      }
   ]
}
```

### Get All Platforms

Retrieve a list of all platforms.

`GET /platform/list`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Request:
```
curl -X GET http://localhost:9000/platform/list -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"
```

###### Response:

```
{
    "platforms": [
        {
            "ID": "653a52481ff613bed613df58",
            "PlatformName": "darwin",
            "Updated_at": "2023-10-26T14:49:28.894+03:00"
        },
        {
            "ID": "653a52401ff613bed613df57",
            "PlatformName": "linux",
            "Updated_at": "2023-10-26T14:49:20.976+03:00"
        }
    ]
}
```

### Get All Architectures

Retrieve a list of all architectures.

`GET /arch/list`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Request:
```
curl -X GET http://localhost:9000/arch/list -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"
```

###### Response:

```
{
    "archs": [
        {
            "ID": "653a52611ff613bed613df59",
            "ArchID": "amd64",
            "Updated_at": "2023-10-26T14:49:53.815+03:00"
        },
        {
            "ID": "653a52691ff613bed613df5a",
            "ArchID": "arm64",
            "Updated_at": "2023-10-26T14:50:01.413+03:00"
        }
    ]
}
```


### Get All Apps

Retrieve a list of all apps.

`GET /`

###### Query Parameters

**limit**: Maximum number of records to return in the response.

###### Headers
**Authorization**: Authorization header with jwt token.

###### Request:
```
curl -X GET http://localhost:9000/ -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"
```

###### Response:

```
{
    "apps": [
        {
            "ID": "653a544c1ff613bed613df5b",
            "AppName": "firstapp",
            "Version": "0.0.1",
            "Channel": "nightly",
            "Published": false,
            "Artifacts": [
                {
                    "Link": "http://localhost:9000/download?key=firstapp/nightly/linux/amd64/firstapp-0.0.1.deb",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".deb"
                }
            ],
            "Changelog": [
                {
                    "Version": "0.0.1",
                    "Changes": "",
                    "Date": "2023-10-26"
                }
            ],
            "Updated_at": "2023-10-26T14:58:04.258+03:00"
        },
        {
            "ID": "653a5e4f51ce5114611f5abb",
            "AppName": "secondapp",
            "Version": "0.0.1",
            "Channel": "stable",
            "Published": true,
            "Artifacts": [
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.1.deb",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".deb"
                },
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.1.rpm",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".rpm"
                }
            ],
            "Changelog": [
                {
                    "Version": "0.0.1",
                    "Changes": "",
                    "Date": "2023-10-26"
                }
            ],
            "Updated_at": "2023-10-26T15:40:47.226+03:00"
        }
    ]
}
```

### Check Latest Version

Check if there is a newer version of a specific app.

`GET /checkVersion?app_name=<app_name>&version=<version>`

###### Query Parameters
**app_name**: Name of the app.

**version**: Current version of the app.

###### Request:
```
curl -X GET --location 'http://localhost:9000/checkVersion?app_name=secondapp&version=0.0.1&channel=stable&platform=linux&arch=amd64'
```

###### Response:

```
{
    "update_available": false,
    "update_url_deb": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.1.deb",
    "update_url_rpm": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.1.rpm"
}
```

### Upload App

Upload a new version of an app.

`POST /upload`

Optional with `channel`, `publish`, `platform`, `arch` and `changelog`:
```
--form 'data="{\"app_name\":\"myapp\",\"version\":\"0.0.1\",\"channel\":\"\",\"publish\":true,\"platform\":\"\",\"arch\":\"\",\"changelog\":\"### Changelog\\n\\n- Added new feature X\\n- Fixed bug Y\"}"'
```
###### Headers
**Authorization**: Authorization header with jwt token.

###### Body
**file**: file of the app.

###### Body form data

**app_name**: Name of the app.

**version**: Current version of the app.

**channel**: Current channel of the app.

**publish**: Set `true` for availabilitty this version for clients.

**critical**: Set `true` to mark this version as critical.

**platform**: Current platform of the app.

**arch**: Current arch of the app.

**changelog**: Changelog is a log of changes on current version. 

###### Request:
```
curl -X POST --location 'http://localhost:9000/upload' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'file=@"/path_to_file/secondapp.deb"' \
--form 'data="{\"app_name\":\"secondapp\",\"version\":\"0.0.2\",\"channel\":\"stable\",\"publish\":true,\"platform\":\"linux\",\"arch\":\"amd64\",\"changelog\":\"### Changelog\\n\\n- Added new feature X\\n- Fixed bug Y\"}"'
```
###### Request with multiple uploading:
```
curl --location 'http://localhost:9000/upload' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'file=@"/path_to_file/secondapp.deb"' \
--form 'file=@"/path_to_file/secondapp.rpm"' \
--form 'data="{\"app_name\":\"secondapp\",\"version\":\"0.0.2\",\"channel\":\"stable\",\"publish\":true,\"platform\":\"linux\",\"arch\":\"amd64\",\"changelog\":\"### Changelog\\n\\n- Added new feature X\\n- Fixed bug Y\"}"'
```
###### Response:

```
{
   "uploadResult.Uploaded":"6411c7c0ec4ff9a9a9bc18fa"
}
```
### Check Latest Version Again

Check if there is a newer version of a specific app after uploading a new version.

`GET /checkVersion?app_name=<app_name>&version=<version>`

###### Query Parameters
**app_name**: Name of the app.

**version**: Current version of the app.

###### Request:
```
curl -X GET --location 'http://localhost:9000/checkVersion?app_name=secondapp&version=0.0.1&channel=stable&platform=linux&arch=amd64'
```

###### Response:

```
{
    "update_available": true,
    "update_url_deb": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.deb",
    "update_url_rpm": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.rpm"
}
```

### Fetch Latest Version of App

This API endpoint retrieves the latest version of a specific app based on the provided parameters.

`GET /apps/latest?app_name=<app_name>&channel=stable&platform=linux&arch=amd64`

###### Query Parameters
**app_name**: Name of the app.

**channel**: Current channel of the app.

**platform**: Current platform of the app.

**arch**: Current arch of the app.

**package**: The package type (e.g., deb, rpm, dmg).

###### Request:
```
curl -X GET --location 'http://localhost:9000/apps/latest?app_name=secondapp&channel=stable&platform=linux&arch=amd64'
```

###### Response:

```
{
  "stable": {
    "linux": {
      "amd64": {
        "deb": {
          "url": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.deb"
        }
      },
      "amd64": {
        "rpm": {
          "url": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.rpm"
        }
      }
    }
  }
}
```

### Update App

Update existing specific app.

:warning: You can't change `app_name`, `channel` and `version`. `app_name` and `version` are used for correct searching.

`POST /apps/update`

Optional with `channel`, `publish`, `critical`, `platform`, `arch` and `changelog`:

data="{\"id\": \"653a6268f51dee6a99a3d88c\", \"app_name\": \"secondapp\", \"version\": \"0.0.2\", \"channel\": \"stable\", \"publish\": true, \"platform\": \"linux\", \"arch\": \"amd64\", \"changelog\": \"\"}"

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body
**file**: file of the app.

###### Body form-data
**app_name**: Name of the app.

**version**: Current version of the app.

**channel**: Current channel of the app.

**publish**: Set `true` for availabilitty this version for clients.

**critical**: Set `true` to mark this version as critical.

**platform**: Current platform of the app.

**arch**: Current arch of the app.

**changelog**: Changelog is a log of changes on current version. 

###### Request:
```
curl --location 'http://localhost:9000/apps/update' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"id\": \"653a6268f51dee6a99a3d88c\", \"app_name\": \"secondapp\", \"version\": \"0.0.2\", \"channel\": \"stable\", \"publish\": true, \"platform\": \"linux\", \"arch\": \"amd64\", \"changelog\": \"\"}"' \
--form 'file=@"/path_to_file/secondapp.deb"' \
```
###### Request with multiple uploading:
```
curl --location 'http://localhost:9000/apps/update' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"id\": \"653a6268f51dee6a99a3d88c\", \"app_name\": \"secondapp\", \"version\": \"0.0.2\", \"channel\": \"stable\", \"publish\": true, \"platform\": \"linux\", \"arch\": \"amd64\", \"changelog\": \"\"}"' \
--form 'file=@"/path_to_file/secondapp.deb"' \
--form 'file=@"/path_to_file/secondapp.rpm"'
```
###### Response:

```
{
    "updatedResult.Updated": true
}
```

### Search App by Name

Search for all versions of an app by name.

`GET /search?app_name=<app_name>`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Query Parameters
**app_name**: Name of the app.

**limit**: Maximum number of records to return in the response.

###### Request:
```
curl -X GET --location 'http://localhost:9000/search?app_name=secondapp' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q'

```

###### Response:

```
{
    "apps": [
        {
            "ID": "653a5e4f51ce5114611f5abb",
            "AppName": "secondapp",
            "Version": "0.0.1",
            "Channel": "stable",
            "Published": true,
            "Artifacts": [
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.1.deb",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".deb"
                },
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.1.rpm",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".rpm"
                }
            ],
            "Changelog": [
                {
                    "Version": "0.0.1",
                    "Changes": "### Changelog\n\n- Added new feature X\n- Fixed bug Y",
                    "Date": "2023-10-26"
                }
            ],
            "Updated_at": "2023-10-26T15:40:47.226+03:00"
        },
        {
            "ID": "653a6268f51dee6a99a3d88c",
            "AppName": "secondapp",
            "Version": "0.0.3",
            "Channel": "stable",
            "Published": true,
            "Artifacts": [
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.deb",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".deb"
                },
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.rpm",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".rpm"
                }
            ],
            "Changelog": [
                {
                    "Version": "0.0.3",
                    "Changes": "### Changelog\n\n- Added new feature X\n- Fixed bug Y",
                    "Date": "2023-10-26"
                }
            ],
            "Updated_at": "2023-10-26T15:58:16.999+03:00"
        }
    ]
}
```

### Delete app
This endpoint allows you to delete a specific app.

`DELETE /app/delete?id=<id>`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Query Parameters
**id**: The unique identifier of the app.

###### Request:
```
curl -X DELETE http://localhost:9000/app/delete\?\id\=\64145ebaedd163d59d52e1dc -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"

```

###### Response:

```
{
   "deleteAppResult.DeletedCount":1
}
```

### Delete specific channel
This endpoint allows you to delete a specific channel.

`DELETE /channel/delete?id=<id>`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Query Parameters
**id**: The unique identifier of the channel.

###### Request:
```
curl -X DELETE http://localhost:9000/channel/delete\?\id\=\64145ebaedd163d59d52e1dc -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"

```

###### Response:

```
{
   "deleteChannelResult.DeletedCount":1
}
```

### Delete specific platform
This endpoint allows you to delete a specific platform.

`DELETE /platform/delete?id=<id>`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Query Parameters
**id**: The unique identifier of the platform.

###### Request:
```
curl -X DELETE http://localhost:9000/platform/delete\?\id\=\64145ebaedd163d59d52e1dc -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"

```

###### Response:

```
{
   "deletePlatformResult.DeletedCount":1
}
```

### Delete specific arch
This endpoint allows you to delete a specific arch.

`DELETE /arch/delete?id=<id>`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Query Parameters
**id**: The unique identifier of the arch.

###### Request:
```
curl -X DELETE http://localhost:9000/arch/delete\?\id\=\64145ebaedd163d59d52e1dc -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"

```

###### Response:

```
{
   "deleteArchResult.DeletedCount":1
}
```

### Delete specific version of app
This endpoint allows you to delete a specific version of an app.

`DELETE /apps/delete?id=<id>`

###### Headers

**Authorization**: Authorization header with jwt token.

###### Query Parameters

**id**: The unique identifier of the app version.

###### Request:
```
curl -X DELETE http://localhost:9000/apps/delete\?\id\=\653a5e4f51ce5114611f5abb -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"

```

###### Response:

```
{
   "deleteSpecificAppResult.DeletedCount":1
}
```

### Check available apps now

`GET /search?app_name=<app_name>`

###### Headers

**Authorization**: Authorization header with jwt token.

###### Query Parameters

**app_name**: Name of the app.

**limit**: Maximum number of records to return in the response.

###### Request:
```
curl -X GET http://localhost:9000/search\?\app_name\=\secondapp -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q"

```

###### Response:
```
{
    "apps": [
        {
            "ID": "653a6268f51dee6a99a3d88c",
            "AppName": "secondapp",
            "Version": "0.0.3",
            "Channel": "stable",
            "Published": true,
            "Artifacts": [
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.deb",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".deb"
                },
                {
                    "Link": "http://localhost:9000/download?key=secondapp/stable/linux/amd64/secondapp-0.0.3.rpm",
                    "Platform": "linux",
                    "Arch": "amd64",
                    "Package": ".rpm"
                }
            ],
            "Changelog": [
                {
                    "Version": "0.0.3",
                    "Changes": "### Changelog\n\n- Added new feature X\n- Fixed bug Y",
                    "Date": "2023-10-26"
                }
            ],
            "Updated_at": "2023-10-26T15:58:16.999+03:00"
        }
    ]
}
```

### Update Channel

Update existing channel.

:warning: If you change this value, already existing client apps can't check for new versions' availability because the channel name has changed.

`POST /channel/update`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body form-data

**id**: ID of the channel which you want to change.

**channel**: New channel name.

###### Request:
```
curl --location 'http://localhost:9000/channel/update' \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q" \
--form 'data="{\"id\":\"66ae13fe4b663c058367f893\", \"channel\":\"new_name\"}"'
```
###### Response:

```
{
    "updateChannelResult.Updated": true
}
```


### Update App

Update existing app.

:warning: If you change this value, already existing client apps can't check for new versions' availability because the app name has changed.

`POST /app/update`

Optional with `description`, `logo`. 

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body
**file**: logo of the app.

###### Body form-data

**id**: ID of the app which you want to change.

**app**: New app name.

**description**: App description.

###### Request:
```
curl --location 'http://localhost:9000/app/update' \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q" \
--form 'data="{\"id\":\"66ae13fe5b663c058367f893\", \"app\":\"new_name\", \"description\": \"description of app\"}"' \
--form 'file=@"path_to_logo.png"'
```
###### Response:

```
{
    "updateAppResult.Updated": true
}
```

### Update Platform

Update existing platform.

:warning: If you change this value, already existing client apps can't check for new versions' availability because the platform name has changed.

`POST /platform/update`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body form-data

**id**: ID of the platform which you want to change.

**platform**: New platform name.

###### Request:
```
curl --location 'http://localhost:9000/platform/update' \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q" \
--form 'data="{\"id\":\"66ae13fe5b663c058367f893\", \"platform\":\"new_name\"}"'
```
###### Response:

```
{
    "updatePlatformResult.Updated": true
}
```

### Update Arch

Update existing arch.

:warning: If you change this value, already existing client apps can't check for new versions' availability because the arch name has changed.

`POST /arch/update`

###### Headers
**Authorization**: Authorization header with jwt token.

###### Body form-data

**id**: ID of the arch which you want to change.

**arch**: New arch name.

###### Request:
```
curl --location 'http://localhost:9000/arch/update' \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q" \
--form 'data="{\"id\":\"66ae13fe5b663c058367f893\", \"arch\":\"new_name\"}"'
```
###### Response:

```
{
    "updateArchResult.Updated": true
}
```

### Delete Artifact

This endpoint allows you to delete artifacts of a specific application by its identifier in array.

`POST /artifact/delete`

###### Headers
**Authorization**: Authorization header with JWT token.

###### Body form-data

**id**: Unique identifier of the specific version of application.

**app_name**: Name of the application to which the artifact belongs.

**version**: Current version of the application.

**artifacts_to_delete**: Array of identifiers of the artifacts to be deleted. Example: ["0", "1"]

###### Request:
```
curl -X POST --location 'http://localhost:9000/artifact/delete' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjY3NDQ4NDMsInVzZXJuYW1lIjoiYWRtaW4ifQ.eYkCNem24-6rpw8aXo6NIcN6xtU9rqq2_2YYz1nS82Q' \
--form 'data="{\"id\":\"653a5e4f51ce5114611f5abb\", \"app_name\":\"secondapp\", \"version\":\"0.0.1\", \"artifacts_to_delete\":[\"0\"]}"'
```

###### Response:

```
{
    "deleteSpecificArtifactResult": true
}
```

### Download

This request returns a signed URL for downloading a file.

`GET /download`

###### Query Parameters

**key**: Key for finding the object on S3.

###### Request:
```
curl -X GET --location 'http://localhost:9000/download?key=secondapp%2Fstable%2Flinux%2Famd64%2Fsecondapp-0.0.1.deb'
```