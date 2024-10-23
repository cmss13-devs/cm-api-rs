# cm-api-rs

This is the backend to [cmdb](https://github.com/cmss13-devs/cmdb), to provide Admins with access to database-stored information from outside the game.

## Configuration

### Api.toml

```toml
[host]
base_url = "/foobar" # if your api is served on a different route

[topic]
host = "play.cm-ss13.com:1400" # which game server should be pinged for status updates
auth = "your-auth-token-here" # the comms key to contact the game server

[logging]
webhook = "some discord webhook" # for actions impacting the database, a discord webhook
```

### Rocket.toml

```toml
[default]
address = "0.0.0.0" # the address the web server should bind to, ie 0.0.0.0 in a container
port = 8080

[default.databases.cmdb]
url = "mysql://root:password@127.0.0.1:3306/cmdb" # pg-esque formatting string
```
