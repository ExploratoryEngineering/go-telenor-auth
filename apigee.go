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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// APIClient is a client used for API-calls towards Apigee.
	// It's set to have sane defaults, but might not be perfect for your use.
	// If so, create new one and adjust accordingly
	APIClient = http.Client{
		Timeout: time.Second * 30,
	}
)

const (
	// apigeeIDCookieName is the name of the cookie used for session management
	apigeeIDCookieName = "goapigee"
)

// TelenorAuth is the main entry point to Telenor Apigee client API.
type TelenorAuth struct {
	Config  ClientConfig
	storage Storage
	mutex   *sync.Mutex
}

// NewDefaultTelenorAuth Provides you with a TelenorAuth with sane defaults
func NewDefaultTelenorAuth() *TelenorAuth {
	return NewTelenorAuth(NewDefaultConfig(ClientConfig{}))
}

// NewTelenorAuth creates a new Telenor Auth client.
func NewTelenorAuth(config ClientConfig) *TelenorAuth {

	if config.ClientID == "" || config.ClientSecret == "" {
		log.Fatalf(`
You need to set both the Client ID and Client Secret.
It can either be set using the config object directly,
or you can set the system environment variables:

ClientId: %s
ClientSecret: %s

For more info check the README for go-telenor-auth`,
			ClientIDEnvVar, ClientSecretEnvVar)
	}

	client := &TelenorAuth{
		Config:  config,
		storage: NewMemoryStorage(),
		mutex:   &sync.Mutex{},
	}

	go client.tokenRefresher()
	return client
}

func (t *TelenorAuth) tokenRefresher() {
	const sleepTime = time.Second * 30
	for {
		time.Sleep(sleepTime)
		t.storage.RefreshTokens(t.Config, sleepTime)
	}
}

// Start the login process
func (t *TelenorAuth) startLogin(w http.ResponseWriter, r *http.Request) {
	randombytes := make([]byte, 10)
	n, err := rand.Read(randombytes)
	if n != len(randombytes) {
		log.Printf("Couldn't read more than %d bytes, requested %d", n, len(randombytes))
	}
	if err != nil {
		log.Printf("Got error reading random bytes: %v", err)
	}

	loginToken := hex.EncodeToString(randombytes)
	if err := t.storage.PutLoginNonce(loginToken); err != nil {
		log.Printf("Error storing token: %v", err)
	}

	newURL := buildApigeeURL(t.Config, apigeeAuthPath)
	q := newURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", t.Config.ClientID)
	q.Set("redirect_uri", t.Config.LoginRedirectURI)
	q.Set("state", loginToken)
	newURL.RawQuery = q.Encode()

	// Remove any old session cookie before starting the roundtrip.
	http.SetCookie(w, &http.Cookie{
		Name:     apigeeIDCookieName,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   t.Config.UseSecureCookie,
		Path:     "/",
	})

	http.Redirect(w, r, newURL.String(), http.StatusSeeOther)
}

// tokenResponse is the response from the apigee token endpoint
type tokenResponse struct {
	AccessToken        string `json:"access_token"`
	AccessTokenExpires string `json:"expires_in"`
	RefreshToken       string `json:"refresh_token"`
}

// Get tokens from code. The returned token response is the output from
// the OAuth service.
func (t *TelenorAuth) getTokens(code string) (tokenResponse, error) {
	nothing := tokenResponse{}
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", t.Config.LoginRedirectURI)
	data.Set("client_id", t.Config.ClientID)

	tokenURL := buildApigeeURL(t.Config, apigeeTokenPath)
	req, err := http.NewRequest("POST", tokenURL.String(), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nothing, fmt.Errorf("Could not create request: %v", err)
	}
	if t.Config.ClientSecret != "" {
		req.SetBasicAuth(t.Config.ClientID, t.Config.ClientSecret)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nothing, fmt.Errorf("Could not execute request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nothing, fmt.Errorf("Could not convert tokens. Expected 200 OK from OAuth server but got %d", resp.StatusCode)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nothing, fmt.Errorf("Could not decode response: %v", err)
	}
	return tokens, nil
}

// Handle the redirect from the OAuth server when login is complete.
func (t *TelenorAuth) loginComplete(w http.ResponseWriter, r *http.Request) {
	// Login is complete - check that code matches the state parameter sent earlier. States
	// are kept for N hours? Mismatch => error page saying "try again"
	// obtain tokens, store token and set cookie
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Verify that state is sent previously
	if err := t.storage.CheckLoginNonce(state); err != nil {
		http.Error(w, "Unknown state token.", http.StatusBadRequest)
		return
	}

	errcode := r.URL.Query().Get("error")
	if errcode != "" {
		// There's an error message. Just redirect back to the logout page.
		log.Printf("Got error from OAuth server: %s - %s", errcode, r.URL.Query().Get("error_description"))
		http.Redirect(w, r, t.Config.LogoutCompleteRedirectURI, http.StatusSeeOther)
		return
	}

	// Validate code and get tokens from server
	tokens, err := t.getTokens(code)
	if err != nil {
		log.Printf("Could not get tokens: %v", err)
		http.Error(w, "Could not pull JWT token from server", http.StatusServiceUnavailable)
		return
	}

	// Create a new session.
	expire, _ := strconv.Atoi(tokens.AccessTokenExpires)
	session := newSession(tokens.AccessToken, tokens.RefreshToken, expire)
	if err := t.storage.PutSession(session); err != nil {
		http.Error(w, "Got error storing session", http.StatusServiceUnavailable)
		return
	}
	cookie := &http.Cookie{
		Name:     apigeeIDCookieName,
		Value:    session.id,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, t.Config.LoginCompleteRedirectURI, http.StatusSeeOther)
}

func (t *TelenorAuth) getSession(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(apigeeIDCookieName)
	if cookie == nil || err == http.ErrNoCookie {
		return Session{}, errors.New("no cookie found")
	}
	session, err := t.storage.GetSession(cookie.Value)
	if err == errorNoSession {
		return Session{}, errors.New("no session found")
	}
	return session, nil
}

// Check if there is a session. Set error and return otherwise
func (t *TelenorAuth) isAuthorized(w http.ResponseWriter, r *http.Request) (bool, Session) {
	cookie, err := r.Cookie(apigeeIDCookieName)
	if cookie == nil || err == http.ErrNoCookie {
		http.Error(w, "You are not authorized to view this page. Try logging in again.", http.StatusUnauthorized)
		return false, Session{}
	}
	session, err := t.storage.GetSession(cookie.Value)
	if err == errorNoSession {
		http.Error(w, "You are not authorized to view this page. Try logging in again.", http.StatusUnauthorized)
		return false, Session{}
	}

	return true, session
}

// Start logout roundtrip
func (t *TelenorAuth) startLogout(w http.ResponseWriter, r *http.Request) {
	randombytes := make([]byte, 10)
	n, err := rand.Read(randombytes)
	if n != len(randombytes) {
		log.Printf("Couldn't read more than %d bytes, requested %d", n, len(randombytes))
	}
	if err != nil {
		log.Printf("Got error reading random bytes: %v", err)
	}

	nonce := hex.EncodeToString(randombytes)
	if err := t.storage.PutLogoutNonce(nonce); err != nil {
		log.Printf("Error storing token: %v", err)
	}

	newURL := buildApigeeURL(t.Config, apigeeLogoutPath)
	q := newURL.Query()
	q.Set("client_id", t.Config.ClientID)
	q.Set("post_logout_redirect_uri", t.Config.LogoutRedirectURI)
	q.Set("state", nonce)
	newURL.RawQuery = q.Encode()
	http.Redirect(w, r, newURL.String(), http.StatusSeeOther)
}

// Handle the redirect from the OAuth server when the logout is complete.
func (t *TelenorAuth) logoutComplete(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("state")
	// Redirect to the default logout no matter what
	defer http.Redirect(w, r, t.Config.LogoutCompleteRedirectURI, http.StatusSeeOther)
	if nonce != "" {
		if err := t.storage.CheckLogoutNonce(nonce); err != nil {
			// Something is broken.
			return
		}
		// Find the user's session
		cookie, err := r.Cookie(apigeeIDCookieName)
		if cookie == nil || err != nil {
			// Something is broken. Redirect to logout
			return
		}
		// Delete session and cookie before redirecting
		t.storage.DeleteSession(cookie.Value)
		http.SetCookie(w, &http.Cookie{Name: apigeeIDCookieName, MaxAge: 0, Expires: time.Now().Add(-1)})
	}
}

type apigeeAuthHandler struct {
	auth *TelenorAuth
}

func (c *apigeeAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, c.auth.Config.LoginInit) {
		c.auth.startLogin(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.auth.Config.LoginRedirect) {
		c.auth.loginComplete(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.auth.Config.LogoutInit) {
		c.auth.startLogout(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.auth.Config.LogoutRedirect) {
		c.auth.logoutComplete(w, r)
		return
	}
	log.Printf("Got auth request to %s but I don't know how to handle it.", r.URL.Path)
	http.Redirect(w, r, c.auth.Config.LogoutCompleteRedirectURI, http.StatusSeeOther)
}

// AuthHandler returns a http.Handler that will respond on the following endpoints:
//
//   Config.LoginInit to start a login roundtrip towards the OAuth server
//   Config.LoginRedirect for the OAuth redirect when login is complete
//   Config.LogoutInit to start a logout roundtrip towards the OAuth server
//   Config.LogoutRedirect for the OAuth redirect when logout is complete
//
// The Init endpoints are the ones you navigate to to initiate the action.
// The Redirect endpoints are redirected to from the OAuth server when it is complete.
func (t *TelenorAuth) AuthHandler() http.Handler {
	return &apigeeAuthHandler{auth: t}
}

// APIProxyHandler Comment
func (t *TelenorAuth) APIProxyHandler() http.Handler {
	return &apiProxyHandler{auth: t}
}
