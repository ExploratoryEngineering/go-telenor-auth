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
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// Partly fetched from https://golang.org/src/net/http/httputil/reverseproxy.go
var ignoreHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {}, // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                {}, // canonicalized version of "TE"
	"Trailer":           {}, // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding": {},
	"Upgrade":           {},
	"Cookie":            {}, // Cookies are not needed towards API endpoint
	"User-Agent":        {}, // Remove old user agent and override with ours
}

const proxyUserAgent = "go-telenor-auth"

type apiProxyHandler struct {
	auth *TelenorAuth
}

// JSONErrorMessage Default JSON response error model
type JSONErrorMessage struct {
	HTTPStatus  int16  `json:"httpStatus"`
	HTTPMessage string `json:"httpMessage"`
	Description string `json:"description"`
	ErrorCode   int16  `json:"errorCode"`
	ResourceID  string `json:"resourceId"`
	Origin      string `json:"origin"`
}

func (c *apiProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v", r.URL)

	session, err := c.auth.getSession(r)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		responseError, _ := json.Marshal(JSONErrorMessage{
			HTTPStatus:  401,
			HTTPMessage: "Unauthorized",
			Description: "No session found. Please log in.",
			ErrorCode:   1,
			ResourceID:  "/api/*",
			Origin:      "Proxy",
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(responseError)
		return
	}

	reqURL := buildApigeeURL(c.auth.Config, strings.TrimLeft(r.RequestURI, c.auth.Config.ProxyPath))

	apiReq, _ := http.NewRequest(r.Method, reqURL.String(), r.Body)
	apiReq.Header.Set("Authorization", "Bearer "+session.accessToken)
	apiReq.Header.Set("user-agent", proxyUserAgent)
	copyHeader(apiReq.Header, r.Header)

	reqDump, _ := httputil.DumpRequest(apiReq, true)
	log.Println(string(reqDump))
	externalRes, err := APIClient.Do(apiReq)
	resDump, _ := httputil.DumpResponse(externalRes, true)
	log.Println(string(resDump))

	if err != nil {
		log.Println(err)
	}

	w.Header().Set("Content-Type", externalRes.Header.Get("Content-Type"))
	w.WriteHeader(externalRes.StatusCode)
	body, _ := ioutil.ReadAll(externalRes.Body)
	externalRes.Body.Close()
	w.Write(body)

}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		_, ignore := ignoreHeaders[k]
		if !ignore {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}
