# API Reference

You can find `Postman` collection [here](examples/SAU.postman_collection.json).

### Check Health Status
Check the health status of the application.

Request:
```
curl -X GET http://localhost:9000/health
```

Responce:

```
{"status":"healthy"}
```

### Login to App
Authenticate and receive a token for accessing the API.

`POST /login`

Request:
```
curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}' http://localhost:9000/login
```

Responce:

```
{"token":"Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"}
```

### Create channel (Optional)

Create deployment channel.

`POST /createChannel\?channel_name\=<channel_name>`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Query Parameters
**channel_name**: Name of the channel.

###### Request:
```
curl -X POST http://localhost:9000/createChannel\?channel_name\=dev -H "Authorization: Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"

```

###### Responce:

```
{
   "createChannelResult.Created":"641459ffb8360d74164e7e3c"
}
```

### Get All Channels

Retrieve a list of all channels.

`GET /listChannels`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Request:
```
curl -X GET http://localhost:9000/listChannels -H "Authorization: Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"
```

###### Responce:

```
{
   "channels":[
      {
         "ID":"641459ffb8360d74164e7e3c",
         "ChannelName":"dev",
         "Updated_at":"2023-03-17T14:15:59.818+02:00"
      },
      {
         "ID":"64145ebaedd163d59d52e1dc",
         "ChannelName":"staging",
         "Updated_at":"2023-03-17T14:36:10.278+02:00"
      }
   ]
}
```

### Get All Apps

Retrieve a list of all apps.

`GET /`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Request:
```
curl -X GET http://localhost:9000/ -H "Authorization: Bearer Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"
```

###### Responce:

```
{
   "apps":[
      {
         "ID":"6409c9c3775729272353fe39",
         "AppName":"myapp",
         "Version":"4.1.5",
         "Link":"https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.1.5",
         "Updated_at":"2023-03-09T13:57:55.546+02:00"
      }
   ]
}
```

### Check Latest Version

Check if there is a newer version of a specific app.

`POST /checkVersion?app_name=<app_name>&version=<version>`

###### Query Parameters
**app_name**: Name of the app.

**version**: Current version of the app.

###### Request:
```
curl -X POST http://localhost:9000/checkVersion\?\app_name=\myapp\&version\=4.1.5
```

###### Responce:

```
{
   "update_available":false,
   "update_url":"https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.1.5.tar.gz"
}
```

### Upload App

Upload a new version of an app.

`POST /upload?app_name=<app_name>&version=<version>`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Query Parameters
**app_name**: Name of the app.

**version**: Current version of the app.

###### Body
**file**: file of the app.


###### Request:
```
curl -X POST -F "file=@/path_to_file/myapp.tar.gz" http://localhost:9000/upload\?\app_name=\myapp\&version\=4.2.3 -H "Authorization: Bearer Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"
```

###### Responce:

```
{
   "uploadResult.Uploaded":"6411c7c0ec4ff9a9a9bc18fa"
}
```
### Check Latest Version Again

Check if there is a newer version of a specific app after uploading a new version.

`POST /checkVersion?app_name=<app_name>&version=<version>`

###### Query Parameters
**app_name**: Name of the app.

**version**: Current version of the app.

###### Request:
```
curl -X POST http://localhost:9000/checkVersion\?\app_name\=\myapp\&version\=4.1.5
```

###### Responce:

```
{
   "update_available":true,
   "update_url":"https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.2.3.tar.gz"
}
```
### Search App by Name

Search for all versions of an app by name.

`GET /search?app_name=<app_name>`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Query Parameters
**app_name**: Name of the app.

###### Request:
```
curl -X GET http://localhost:9000/search\?\app_name\=\myapp -H "Authorization: Bearer Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"

```

###### Responce:

```
{
   "apps":[
      {
         "ID":"640a0edae692cadeb0e5bc47",
         "AppName":"myapp",
         "Version":"4.1.5",
         "Link":"https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.1.5.tar.gz",
         "Updated_at":"2023-03-09T18:52:42.573+02:00"
      }{
         "ID":"6411c7c0ec4ff9a9a9bc18fa",
         "AppName":"myapp",
         "Version":"4.2.3",
         "Link":"https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.2.3.tar.gz",
         "Updated_at":"2023-03-15T15:27:28.807+02:00"
      }
   ]
}
```
### Delete specific channel
This endpoint allows you to delete a specific channel.

`DELETE /deleteChannel?id=<id>`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Query Parameters
**id**: The unique identifier of the channel.

###### Request:
```
curl -X DELETE http://localhost:9000/deleteChannel\?\id\=\64145ebaedd163d59d52e1dc -H "Authorization: Bearer Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"

```

###### Responce:

```
{
   "deleteChannelResult.DeletedCount":1
}
```

### Delete specific version of app
This endpoint allows you to delete a specific version of an app.

`DELETE /deleteApp?id=<id>`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Query Parameters
**id**: The unique identifier of the app version.

###### Request:
```
curl -X DELETE http://localhost:9000/deleteApp\?\id\=\640a0edae692cadeb0e5bc47 -H "Authorization: Bearer Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"

```

###### Responce:

```
{
   "deleteAppResult.DeletedCount":1
}
```

### Check available apps now

`GET /search?app_name=<app_name>`

###### Headers
**Authorization**: Authorization header with encoded username and password.

###### Query Parameters
**app_name**: Name of the app.

###### Request:
```
curl -X GET http://localhost:9000/search\?\app_name\=\myapp -H "Authorization: Bearer Ut5b4fQs05UbTteme2jK4A6394_K2uxfbBTRueW-U1px4Jl9QbZ_Hd7o"

```

###### Responce:
```
{
   "apps":[
      {
         "ID":"6411c7c0ec4ff9a9a9bc18fa",
         "AppName":"myapp",
         "Version":"4.2.3",
         "Link":"https://<bucket_name>.s3.amazonaws.com/myapp/myapp-4.2.3.tar.gz",
         "Updated_at":"2023-03-15T15:27:28.807+02:00"
      }
   ]
}
```