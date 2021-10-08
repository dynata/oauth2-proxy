package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

var severCount = 0

// These constant is used to define server
// TEST SERVERS
const (
	SERVER1 = "http://localhost:8080"
	SERVER2 = "http://localhost:8080"
	SERVER3 = "http://localhost:8080"
	PORT    = "1338"
)

type DebugTransport struct{}

func (DebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	_, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		log.Printf("dump upstream request error: %s\n", err)
		return nil, err
	}
	// fmt.Println(string(dump))
	return http.DefaultTransport.RoundTrip(req)
}

func modifyResponse(p *OAuthProxy) func(*http.Response) error {
	return func(resp *http.Response) error {
		// resp.Header.Set("X-Proxy", "Magical")

		_, err := httputil.DumpResponse(resp, false)
		if err != nil {
			log.Printf("dump upstream response error: %s\n", err)
			return err
		}
		// fmt.Println(string(dump))

		/* if resp.Request.URL.Path == p.provider.Data().IssuerURL.Path+"/.well-known/openid-configuration" {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			err = resp.Body.Close()
			if err != nil {
				return err
			}

			var data map[string]interface{}
			err = json.Unmarshal(body, &data)
			if err != nil {
				return err
			}

			// data["grant_types_supported"] = []string{"authorization_code", "refresh_token", "password"}
			// data["response_types_supported"] = []string{"code"}

			respBytes, err := json.Marshal(&data)
			if err != nil {
				return err
			}

			respBody := ioutil.NopCloser(bytes.NewReader(respBytes))
			resp.Body = respBody
			resp.ContentLength = int64(len(respBytes))
			resp.Header.Set("Content-Length", strconv.Itoa(len(respBytes)))
		} */

		return nil
	}
}

func ReverseProxy(target string, p *OAuthProxy) *httputil.ReverseProxy {
	// parse the url
	url, _ := url.Parse(target)
	log.Printf("forwarding to -> %s\n", url)
	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// proxy.Transport = DebugTransport{}
	if p != nil {
		proxy.ModifyResponse = modifyResponse(p)
	}

	return proxy
}

// Serve a reverse proxy for a given url
func serveReverseProxy(target string, res http.ResponseWriter, req *http.Request) {
	proxy := ReverseProxy(target, nil)
	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}

// Log the typeform payload and redirect url
func logRequestPayload(proxyURL string) {
	log.Printf("proxy_url: %s\n", proxyURL)
}

// Balance returns one of the servers based using round-robin algorithm
func getProxyURL() string {
	var servers = []string{SERVER1, SERVER2, SERVER3}

	server := servers[severCount]
	severCount++

	// reset the counter and start from the beginning
	if severCount >= len(servers) {
		severCount = 0
	}

	return server
}

// Given a request send it to the appropriate url
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	url := getProxyURL()

	logRequestPayload(url)

	serveReverseProxy(url, res, req)
}

func TestReverseProxy() {
	// start server
	http.HandleFunc("/", handleRequestAndRedirect)

	log.Fatal(http.ListenAndServe(":"+PORT, nil))
}
