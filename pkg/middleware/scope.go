package middleware

import (
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

type redirectValidatorFunc func(redirect string, defaultAppRedirectURL *url.URL, whitelistDomains []string) bool

func NewScope(reverseProxy bool, idHeader string) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := &middlewareapi.RequestScope{
				ReverseProxy: reverseProxy,
				RequestID:    genRequestID(req, idHeader),
			}
			req = middlewareapi.AddRequestScope(req, scope)
			next.ServeHTTP(rw, req)
		})
	}
}

func NewScopeUsingOptions(opts *options.Options) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := &middlewareapi.RequestScope{
				ReverseProxy: opts.ReverseProxy,
				RequestID:    genRequestID(req, opts.Logging.RequestIDHeader),
				AllClientIDs: opts.GetAllClientIDs(),
			}
			req = middlewareapi.AddRequestScope(req, scope)
			next.ServeHTTP(rw, req)
		})
	}
}

func SetupCORS(rvf redirectValidatorFunc, defaultAppRedirectURL *url.URL, whitelistDomains []string) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			origin := req.Header.Get("Origin")
			isRequestURLValid := rvf(origin, defaultAppRedirectURL, whitelistDomains)
			if isRequestURLValid {
				rw.Header().Set("Access-Control-Allow-Origin", origin)
				rw.Header().Set("Access-Control-Allow-Headers", "*")
				rw.Header().Set("Access-Control-Allow-Credentials", "true")
				rw.Header().Set("Vary", "Origin")
			}
			next.ServeHTTP(rw, req)
		})
	}
}

// genRequestID sets a request-wide ID for use in logging or error pages.
// If a RequestID header is set, it uses that. Otherwise, it generates a random
// UUID for the lifespan of the request.
func genRequestID(req *http.Request, idHeader string) string {
	rid := req.Header.Get(idHeader)
	if rid != "" {
		return rid
	}
	return uuid.New().String()
}
