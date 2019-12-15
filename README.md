# RTMessenger
This was compiled using Go 1.13.4 (but most recent versions should be OK) on Ubuntu 18.04.

To install the latest Go compiler and runtime, use `sudo snap install --classic go`.

To run this, put the Assignment4 directory in `~/go/src/github.com/parkerottaway/`.

`~/go/src/` is the default $GOHOME.

To run the client, go to `~/go/src/github.com/parkerottaway/Assignment4/Client` and do `go run main.go`.

To run the server, go to `~/go/src/github.com/parkerottaway/Assignment4/Server` and do `go run main.go`.

## Client Functions

### Exit
Exit the client program with `exit`.
### Login
Use `login#<USERNAME>&<PASSWORD>`, where `<USERNAME>` is the username and `<PASSWORD>`. is the password, to login with one of the possible enumerated sessions.
### Logout
Use `logout#` to log out of an account.
### Post
Use `post#<MESSAGE>` to send a post with message `<MESSAGE>` to the server. If you are not logged in, you cannot post. Specifically posting `RESET` to the server triggers a client reset, and the client is logged out.
### Subscribe
Client can subscribe to other users with `subscribe#<USER>` to receive real-time posts and be able to retrieve their previous posts.
### Unsubscribe
Use `unsubscribe#<USER>` to unsubscribe to no loger receive real-time posts or see their previous posts.
### Retrieve
Client can retrieve the n most recent posts by subscribed clients with `retrieve#n`, returned to the user in chronological order. Where n must be a natural number.
### All other operations
All other operations trigger a session reset and log the client out.

The server has no operations, it just exists passively and parese the users.txt file to build session list.
