# go-telenor-auth
A simple integration towards Telenor Apigee using golang

## Usage

Add `"github.com/ExploratoryEngineering/go-telenor-auth"` to your imports


### Configuring


#### Simple

The simplest way of configuring the lib is as following

```go
telenorAuth := gotelenorauth.NewDefaultTelenorAuth()
```

This will expect that you have set the environment variables for both the client ID and client secret. If the library can't find it, it will throw a fatal error and fail to start.

The environment variables are named the following:
 - ClientId: APIGEE_CLIENT_ID
 - ClientSecret: APIGEE_CLIENT_SECRET

 These can be found when registering at https://developer.telenor.no and after the creation of a new application.


#### With custom config
```go
telenorAuth := gotelenorauth.NewTelenorAuth(
		gotelenorauth.NewDefaultConfig(gotelenorauth.ClientConfig{
			ClientID:                  "",                                          // Host is the name of the Telenor API host to use.
			ClientSecret:              "",                                          // ClientID is the OAuth client ID.
			Host:                      "api.telenor.no",                            // ClientSecret is the client secret.
			LoginInit:                 "login",                                     // LoginInit is the endpoint for starting a login.
			LogoutInit:                "logout",                                    // LogoutInit is the endpoint for starting a logout.
			LoginRedirectURI:          "http://localhost:8080/auth/oauth2callback", // LoginRedirectURI is where the OAuth server redirects after a successful login.
			LoginRedirect:             "oauth2callback",                            // LoginRedirect is the endpoint that serves - and is thus typically a suffix of - LoginRedirectURI.
			LoginCompleteRedirectURI:  "/",                                         // LoginCompleteRedirectURI is where go-telenor-auth redirects after a successful login.
			LogoutCompleteRedirectURI: "/",                                         // LogoutCompleteRedirectURI is where go-telenor-auth redirects after a successfull logout.
			ProxyPath:                 "/api/",                                     // ProxyPath The path of the API proxy which proxes calls to given host with credentials.
			UseSecureCookie:           false,                                       // UseSecureCookie indicates whether to use a secure cookie.
		}))
```

All of the fields are customizable, but the defaults should work in almost every case.

### Adding login/logout
To add the login/logout routes use following code:

```go
	// Add login/logout handling
	http.Handle("/auth/", telenorAuth.AuthHandler())
```

This will add the following routes (with default configuration):
 - `/auth/login` - The initiator of a new login
 - `/auth/logout` - The initiator of a new logout
 - `/auth/oauth2callback` - Callback from the Telenor API server to validate OAuth token
 - `/auth/logoutcallback` - Callback from the Telenor API server when successful logout

### Protecting a route

To protect a route you can use the following code:

```go
	// Paths will be secured by Telenor Auth login
	http.Handle("/secure/", telenorAuth.NewAuthHandlerFunc(secretHTTPHandler))
```

This will wrap the `secretHTTPHandler` in a step which checks for an active session for the request. You have to implement the `secretHTTPHandler` yourself as a normal `http.Handler`.

### Adding API proxy

To access the APIs from Telenor you could either fetch the session and manually use the token in an `Authorization`-header, or you could use the built in simple-proxy to communicate with Telenors APIs.

To add the proxy use the following code:
```go
	// Add proxy to api.telenor.no
	http.Handle(telenorAuth.Config.ProxyPath, telenorAuth.APIProxyHandler())
```

This will add a proxy for `/api/*` (with default configuration). This means that if you want to access an API at https://api.telenor.no with the path `telenor-stores/v1`, you can use the proxy at `localhost:8080/api/telenor-stores/v1` to access the data with the logged in session. Remember that the user has to be logged in to access the APIs.


### Full working example

The following code shows a fully configured server with different routes, AuthHandler and an API proxy:

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/ExploratoryEngineering/go-telenor-auth"
)

func main() {

	telenorAuth := gotelenorauth.NewDefaultTelenorAuth()

	// Add login/logout handling
	http.Handle("/auth/", telenorAuth.AuthHandler())

	// Add /api/*
	http.Handle(telenorAuth.Config.ProxyPath, telenorAuth.APIProxyHandler())

	// Add paths you want secured
	http.Handle("/secure/", telenorAuth.NewAuthHandlerFunc(everythingIsOKButSecret))

	// Catch all/fallback
	http.HandleFunc("/", everythingIsOK)
	// Start server
	http.ListenAndServe(":8080", nil)
}

func everythingIsOK(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Everything is OK")
	w.Write([]byte("Everything is OK"))
}

func everythingIsOKButSecret(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Everything is OK, but SECRET")
	w.Write([]byte("Everything is OK, but SECRET"))
}
```