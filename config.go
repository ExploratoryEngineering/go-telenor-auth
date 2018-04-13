package gotelenorauth

/*
**   Copyright 2018 Telenor Digital AS
**
**  Licensed under the Apache License, Version 2.0 (the "License");
**  you may not use this file except in compliance with the License.
**  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
 */
import (
	"net/url"
	"os"
)

const (
	apigeeScheme     = "https"
	apigeeAuthPath   = "/oauth/v2/authorize"
	apigeeTokenPath  = "/oauth/v2/token"
	apigeeLogoutPath = "/oauth/v2/logout"
)

const (
	// DefaultHost is the Telenor Apigee production host. We recommend using this.
	DefaultHost = "api.telenor.no"

	// StagingHost is the host name for the staging (aka testing) environment
	StagingHost = "test-api.telenor.no"
)

// These constants provide default values for ClientConfig.
const (
	DefaultLoginInit  = "login"
	DefaultLogoutInit = "logout"

	DefaultLoginRedirectURI = "http://localhost:8080/auth/oauth2callback"
	DefaultLoginRedirect    = "oauth2callback"

	DefaultLoginCompleteRedirectURI  = "/"
	DefaultLogoutCompleteRedirectURI = "/"

	DefaultProxyPath   = "/api/"
	ClientIDEnvVar     = "APIGEE_CLIENT_ID"
	ClientSecretEnvVar = "APIGEE_CLIENT_SECRET"
)

// ClientConfig holds the Apigee Auth configuration.
type ClientConfig struct {
	Host string // Host is the name of the Telenor API host to use.

	ClientID     string // ClientID is the OAuth client ID.
	ClientSecret string // ClientSecret is the client secret.

	LoginInit  string // LoginInit is the endpoint for starting a login.
	LogoutInit string // LogoutInit is the endpoint for starting a logout.

	LoginRedirectURI string // LoginRedirectURI is where the OAuth server redirects after a successful login.
	LoginRedirect    string // LoginRedirect is the endpoint that serves - and is thus typically a suffix of - LoginRedirectURI.

	LoginCompleteRedirectURI  string // LoginCompleteRedirectURI is where go-telenor-auth redirects after a successful login.
	LogoutCompleteRedirectURI string // LogoutCompleteRedirectURI is where go-telenor-auth redirects after a successfull logout.

	ProxyPath string // ProxyPath The path of the API proxy which proxes calls to given host with credentials.

	UseSecureCookie bool // UseSecureCookie indicates whether to use a secure cookie.
}

// NewDefaultConfig creates a configuration with default values prepopulated. If the
// parameter is set in the overrides parameter it won't be set.
func NewDefaultConfig(overrides ClientConfig) ClientConfig {
	ret := overrides
	if ret.ClientID == "" {
		ret.ClientID = os.Getenv(ClientIDEnvVar)
	}
	if ret.ClientSecret == "" {
		ret.ClientSecret = os.Getenv(ClientSecretEnvVar)
	}
	if ret.Host == "" {
		ret.Host = DefaultHost
	}
	if ret.LoginInit == "" {
		ret.LoginInit = DefaultLoginInit
	}
	if ret.LogoutInit == "" {
		ret.LogoutInit = DefaultLogoutInit
	}
	if ret.LoginRedirectURI == "" {
		ret.LoginRedirectURI = DefaultLoginRedirectURI
	}
	if ret.LoginRedirect == "" {
		ret.LoginRedirect = DefaultLoginRedirect
	}
	if ret.LoginCompleteRedirectURI == "" {
		ret.LoginCompleteRedirectURI = DefaultLoginCompleteRedirectURI
	}
	if ret.LogoutCompleteRedirectURI == "" {
		ret.LogoutCompleteRedirectURI = DefaultLogoutCompleteRedirectURI
	}
	if ret.ProxyPath == "" {
		ret.ProxyPath = DefaultProxyPath
	}
	return ret
}

// Helper function to construct an URL for requests
func buildApigeeURL(config ClientConfig, path string) url.URL {
	return url.URL{
		Scheme: apigeeScheme,
		Host:   config.Host,
		Path:   path,
	}
}
