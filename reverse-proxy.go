package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type responseModifiers func(rw http.ResponseWriter, req *http.Request, resp *http.Response)

func errorHandler(res http.ResponseWriter, req *http.Request, err error) {
	log.Printf("reverse proxy forwarding error: %s\n", err)
}

func modifyResponse(modifiers []responseModifiers, rw http.ResponseWriter) func(*http.Response) error {
	return func(resp *http.Response) error {
		req := resp.Request
		for i := range modifiers {
			modifier := modifiers[i]
			modifier(rw, req, resp)
		}
		return nil
	}
}

func NewReverseProxy(target string) *httputil.ReverseProxy {
	// parse the url
	targetURL, _ := url.Parse(target)
	log.Printf("forwarding to reverse proxy -> %s\n", targetURL)
	// create the reverse proxy
	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)

	defaultDirector := reverseProxy.Director
	director := func(req *http.Request) {
		defaultDirector(req)
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	reverseProxy.Transport = transport
	reverseProxy.Director = director
	reverseProxy.ErrorHandler = errorHandler

	return reverseProxy
}

func reverseProxyAddModifiers(reverseProxy *httputil.ReverseProxy, modifiers []responseModifiers, rw http.ResponseWriter) *httputil.ReverseProxy {
	reverseProxy.ModifyResponse = modifyResponse(modifiers, rw)
	return reverseProxy
}
