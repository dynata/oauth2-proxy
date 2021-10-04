package main

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/constants"
	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication/basic"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	proxyhttp "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/upstream"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

const (
	schemeHTTP      = "http"
	schemeHTTPS     = "https"
	applicationJSON = "application/json"
)

var (
	// ErrNeedsLogin means the user should be redirected to the login page
	ErrNeedsLogin = errors.New("redirect to login page")

	// ErrAccessDenied means the user should receive a 401 Unauthorized response
	ErrAccessDenied = errors.New("access denied")

	// Used to check final redirects are not susceptible to open redirects.
	// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
	invalidRedirectRegex = regexp.MustCompile(`[/\\](?:[\s\v]*|\.{1,2})[/\\]`)
)

// allowedRoute manages method + path based allowlists
type allowedRoute struct {
	method    string
	pathRegex *regexp.Regexp
}

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieOptions *options.Cookie
	Validator     func(string) bool

	RobotsPath        string
	SignInPath        string
	SignOutPath       string
	OAuthStartPath    string
	OAuthCallbackPath string
	AuthOnlyPath      string
	UserInfoPath      string

	allowedRoutes         []allowedRoute
	redirectURL           *url.URL // the url to receive requests at
	defaultAppRedirectURL *url.URL
	whitelistDomains      []string
	provider              providers.Provider
	sessionStore          sessionsapi.SessionStore
	ProxyPrefix           string
	basicAuthValidator    basic.Validator
	serveMux              http.Handler
	SkipProviderButton    bool
	skipAuthPreflight     bool
	skipJwtBearerTokens   bool
	realClientIPParser    ipapi.RealClientIPParser
	trustedIPs            *ip.NetSet

	sessionLoader *middleware.StoredSessionLoader
	sessionChain  alice.Chain
	headersChain  alice.Chain
	preAuthChain  alice.Chain
	pageWriter    pagewriter.Writer
	server        proxyhttp.Server
}

type authServerTokenResponse struct {
	TokenType             string  `json:"token_type"`
	IDToken               string  `json:"id_token"`
	RefreshToken          string  `json:"refresh_token"`
	RefreshTokenExpiresIn float64 `json:"refresh_expires_in"`
	AccessToken           string  `json:"access_token"`
	ExpiresIn             float64 `json:"expires_in"`
	Scope                 string  `json:"scope"`
	SessionState          string  `json:"session_state"`
}

// NewOAuthProxy creates a new instance of OAuthProxy from the options provided
func NewOAuthProxy(opts *options.Options, validator func(string) bool) (*OAuthProxy, error) {
	sessionStore, err := sessions.NewSessionStore(&opts.Session, &opts.Cookie)
	if err != nil {
		return nil, fmt.Errorf("error initialising session store: %v", err)
	}

	var basicAuthValidator basic.Validator
	if opts.HtpasswdFile != "" {
		logger.Printf("using htpasswd file: %s", opts.HtpasswdFile)
		var err error
		basicAuthValidator, err = basic.NewHTPasswdValidator(opts.HtpasswdFile)
		if err != nil {
			return nil, fmt.Errorf("could not load htpasswdfile: %v", err)
		}
	}

	pageWriter, err := pagewriter.NewWriter(pagewriter.Opts{
		TemplatesPath:    opts.Templates.Path,
		CustomLogo:       opts.Templates.CustomLogo,
		ProxyPrefix:      opts.ProxyPrefix,
		Footer:           opts.Templates.Footer,
		Version:          VERSION,
		Debug:            opts.Templates.Debug,
		ProviderName:     buildProviderName(opts.GetProvider(), opts.Providers[0].Name),
		SignInMessage:    buildSignInMessage(opts),
		DisplayLoginForm: basicAuthValidator != nil && opts.Templates.DisplayLoginForm,
	})
	if err != nil {
		return nil, fmt.Errorf("error initialising page writer: %v", err)
	}

	upstreamProxy, err := upstream.NewProxy(opts.UpstreamServers, opts.GetSignatureData(), pageWriter)
	if err != nil {
		return nil, fmt.Errorf("error initialising upstream proxy: %v", err)
	}

	if opts.SkipJwtBearerTokens {
		logger.Printf("Skipping JWT tokens from configured OIDC issuer: %q", opts.Providers[0].OIDCConfig.IssuerURL)
		for _, issuer := range opts.ExtraJwtIssuers {
			logger.Printf("Skipping JWT tokens from extra JWT issuer: %q", issuer)
		}
	}
	redirectURL := opts.GetRedirectURL()
	if redirectURL.Path == "" {
		redirectURL.Path = fmt.Sprintf("%s/callback", opts.ProxyPrefix)
	}

	defaultAppRedirectURL := opts.GetDefaultAppRedirectURL()

	logger.Printf("OAuthProxy configured for %s Client ID: %s", opts.GetProvider().Data().ProviderName, opts.Providers[0].ClientID)
	refresh := "disabled"
	if opts.Cookie.Refresh != time.Duration(0) {
		refresh = fmt.Sprintf("after %s", opts.Cookie.Refresh)
	}

	logger.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domains:%s path:%s samesite:%s refresh:%s cookie-code-validity-expire:%s", opts.Cookie.Name, opts.Cookie.Secure, opts.Cookie.HTTPOnly, opts.Cookie.Expire, strings.Join(opts.Cookie.Domains, ","), opts.Cookie.Path, opts.Cookie.SameSite, refresh, opts.Cookie.CodeValidityDuration)

	trustedIPs := ip.NewNetSet()
	for _, ipStr := range opts.TrustedIPs {
		if ipNet := ip.ParseIPNet(ipStr); ipNet != nil {
			trustedIPs.AddIPNet(*ipNet)
		} else {
			return nil, fmt.Errorf("could not parse IP network (%s)", ipStr)
		}
	}

	allowedRoutes, err := buildRoutesAllowlist(opts)
	if err != nil {
		return nil, err
	}

	provider := opts.GetProvider()

	preAuthChain, err := buildPreAuthChain(opts)
	if err != nil {
		return nil, fmt.Errorf("could not build pre-auth chain: %v", err)
	}
	sessionChain, sessionLoader := buildSessionChain(opts, sessionStore, basicAuthValidator, provider)
	headersChain, err := buildHeadersChain(opts)
	if err != nil {
		return nil, fmt.Errorf("could not build headers chain: %v", err)
	}

	p := &OAuthProxy{
		CookieOptions: &opts.Cookie,
		Validator:     validator,

		RobotsPath:        "/robots.txt",
		SignInPath:        fmt.Sprintf("%s/sign_in", opts.ProxyPrefix),
		SignOutPath:       fmt.Sprintf("%s/sign_out", opts.ProxyPrefix),
		OAuthStartPath:    fmt.Sprintf("%s/start", opts.ProxyPrefix),
		OAuthCallbackPath: fmt.Sprintf("%s/callback", opts.ProxyPrefix),
		AuthOnlyPath:      fmt.Sprintf("%s/auth", opts.ProxyPrefix),
		UserInfoPath:      fmt.Sprintf("%s/userinfo", opts.ProxyPrefix),

		ProxyPrefix:           opts.ProxyPrefix,
		provider:              provider,
		sessionStore:          sessionStore,
		serveMux:              upstreamProxy,
		redirectURL:           redirectURL,
		defaultAppRedirectURL: defaultAppRedirectURL,
		allowedRoutes:         allowedRoutes,
		whitelistDomains:      opts.WhitelistDomains,
		skipAuthPreflight:     opts.SkipAuthPreflight,
		skipJwtBearerTokens:   opts.SkipJwtBearerTokens,
		realClientIPParser:    opts.GetRealClientIPParser(),
		SkipProviderButton:    opts.SkipProviderButton,
		trustedIPs:            trustedIPs,

		basicAuthValidator: basicAuthValidator,
		sessionLoader:      sessionLoader,
		sessionChain:       sessionChain,
		headersChain:       headersChain,
		preAuthChain:       preAuthChain,
		pageWriter:         pageWriter,
	}

	if err := p.setupServer(opts); err != nil {
		return nil, fmt.Errorf("error setting up server: %v", err)
	}

	return p, nil
}

func (p *OAuthProxy) Start() error {
	if p.server == nil {
		// We have to call setupServer before Start is called.
		// If this doesn't happen it's a programming error.
		panic("server has not been initialised")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Observe signals in background goroutine.
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint
		cancel() // cancel the context
	}()

	return p.server.Start(ctx)
}

func (p *OAuthProxy) setupServer(opts *options.Options) error {
	serverOpts := proxyhttp.Opts{
		Handler:           p,
		BindAddress:       opts.Server.BindAddress,
		SecureBindAddress: opts.Server.SecureBindAddress,
		TLS:               opts.Server.TLS,
	}

	appServer, err := proxyhttp.NewServer(serverOpts)
	if err != nil {
		return fmt.Errorf("could not build app server: %v", err)
	}

	metricsServer, err := proxyhttp.NewServer(proxyhttp.Opts{
		Handler:           middleware.DefaultMetricsHandler,
		BindAddress:       opts.MetricsServer.BindAddress,
		SecureBindAddress: opts.MetricsServer.SecureBindAddress,
		TLS:               opts.MetricsServer.TLS,
	})
	if err != nil {
		return fmt.Errorf("could not build metrics server: %v", err)
	}

	p.server = proxyhttp.NewServerGroup(appServer, metricsServer)
	return nil
}

// buildPreAuthChain constructs a chain that should process every request before
// the OAuth2 Proxy authentication logic kicks in.
// For example forcing HTTPS or health checks.
func buildPreAuthChain(opts *options.Options) (alice.Chain, error) {
	chain := alice.New(middleware.NewScope(opts.ReverseProxy, opts.Logging.RequestIDHeader))

	if opts.ForceHTTPS {
		_, httpsPort, err := net.SplitHostPort(opts.Server.SecureBindAddress)
		if err != nil {
			return alice.Chain{}, fmt.Errorf("invalid HTTPS address %q: %v", opts.Server.SecureBindAddress, err)
		}
		chain = chain.Append(middleware.NewRedirectToHTTPS(httpsPort))
	}

	healthCheckPaths := []string{opts.PingPath}
	healthCheckUserAgents := []string{opts.PingUserAgent}
	if opts.GCPHealthChecks {
		logger.Printf("WARNING: GCP HealthChecks are now deprecated: Reconfigure apps to use the ping path for liveness and readiness checks, set the ping user agent to \"GoogleHC/1.0\" to preserve existing behaviour")
		healthCheckPaths = append(healthCheckPaths, "/liveness_check", "/readiness_check")
		healthCheckUserAgents = append(healthCheckUserAgents, "GoogleHC/1.0")
	}

	// To silence logging of health checks, register the health check handler before
	// the logging handler
	if opts.Logging.SilencePing {
		chain = chain.Append(
			middleware.NewHealthCheck(healthCheckPaths, healthCheckUserAgents),
			middleware.NewRequestLogger(),
		)
	} else {
		chain = chain.Append(
			middleware.NewRequestLogger(),
			middleware.NewHealthCheck(healthCheckPaths, healthCheckUserAgents),
		)
	}

	chain = chain.Append(middleware.NewRequestMetricsWithDefaultRegistry())

	return chain, nil
}

func buildSessionChain(opts *options.Options, sessionStore sessionsapi.SessionStore,
	validator basic.Validator, provider providers.Provider) (alice.Chain, *middleware.StoredSessionLoader) {
	chain := alice.New()

	if opts.SkipJwtBearerTokens {
		sessionLoaders := []middlewareapi.TokenToSessionFunc{
			opts.GetProvider().CreateSessionFromToken,
		}

		for _, verifier := range opts.GetJWTBearerVerifiers() {
			sessionLoaders = append(sessionLoaders,
				middlewareapi.CreateTokenToSessionFunc(verifier.Verify))
		}

		chain = chain.Append(middleware.NewJwtSessionLoader(sessionLoaders))
	}

	if validator != nil {
		chain = chain.Append(middleware.NewBasicAuthSessionLoader(validator, opts.HtpasswdUserGroups, opts.LegacyPreferEmailToUser))
	}

	sessionLoaderOpts := &middleware.StoredSessionLoaderOptions{
		SessionStore:           sessionStore,
		RefreshPeriod:          opts.Cookie.Refresh,
		ProviderData:           opts.GetProvider().Data(),
		RefreshSessionIfNeeded: opts.GetProvider().RefreshSessionIfNeeded,
		ValidateSessionState:   opts.GetProvider().ValidateSession,
	}

	sessionLoader := middleware.GenerateSessionLoader(sessionLoaderOpts)

	sessionLoaderMiddleware := middleware.NewStoredSessionLoaderFromInstance(sessionLoader)

	chain = chain.Append(sessionLoaderMiddleware)

	return chain, sessionLoader
}

func buildHeadersChain(opts *options.Options) (alice.Chain, error) {
	requestInjector, err := middleware.NewRequestHeaderInjector(opts.InjectRequestHeaders)
	if err != nil {
		return alice.Chain{}, fmt.Errorf("error constructing request header injector: %v", err)
	}

	responseInjector, err := middleware.NewResponseHeaderInjector(opts.InjectResponseHeaders)
	if err != nil {
		return alice.Chain{}, fmt.Errorf("error constructing request header injector: %v", err)
	}

	return alice.New(requestInjector, responseInjector), nil
}

func buildSignInMessage(opts *options.Options) string {
	var msg string
	if len(opts.Templates.Banner) >= 1 {
		if opts.Templates.Banner == "-" {
			msg = ""
		} else {
			msg = opts.Templates.Banner
		}
	} else if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			msg = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			msg = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}
	return msg
}

func buildProviderName(p providers.Provider, override string) string {
	if override != "" {
		return override
	}
	return p.Data().ProviderName
}

// buildRoutesAllowlist builds an []allowedRoute  list from either the legacy
// SkipAuthRegex option (paths only support) or newer SkipAuthRoutes option
// (method=path support)
func buildRoutesAllowlist(opts *options.Options) ([]allowedRoute, error) {
	routes := make([]allowedRoute, 0, len(opts.SkipAuthRegex)+len(opts.SkipAuthRoutes))

	for _, path := range opts.SkipAuthRegex {
		compiledRegex, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}
		logger.Printf("Skipping auth - Method: ALL | Path: %s", path)
		routes = append(routes, allowedRoute{
			method:    "",
			pathRegex: compiledRegex,
		})
	}

	for _, methodPath := range opts.SkipAuthRoutes {
		var (
			method string
			path   string
		)

		parts := strings.SplitN(methodPath, "=", 2)
		if len(parts) == 1 {
			method = ""
			path = parts[0]
		} else {
			method = strings.ToUpper(parts[0])
			path = parts[1]
		}

		compiledRegex, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}
		logger.Printf("Skipping auth - Method: %s | Path: %s", method, path)
		routes = append(routes, allowedRoute{
			method:    method,
			pathRegex: compiledRegex,
		})
	}

	return routes, nil
}

// ClearSessionCookie creates a cookie to unset the user's authentication cookie
// stored in the user's session
func (p *OAuthProxy) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) error {
	return p.sessionStore.Clear(rw, req)
}

// LoadCookiedSession reads the user's authentication details from the request
func (p *OAuthProxy) LoadCookiedSession(req *http.Request) (*sessionsapi.SessionState, error) {
	return p.sessionStore.Load(req)
}

// SaveSession creates a new session cookie value and sets this on the response
func (p *OAuthProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) (string, error) {
	return p.sessionStore.Save(rw, req, s)
}

// IsValidRedirect checks whether the redirect URL is whitelisted
func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
	switch {
	case redirect == "":
		// The user didn't specify a redirect, should fallback to `/`
		return false
	case redirect == p.defaultAppRedirectURL.String():
		return true
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !invalidRedirectRegex.MatchString(redirect):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			logger.Printf("Rejecting invalid redirect %q: scheme unsupported or missing", redirect)
			return false
		}
		redirectHostname := redirectURL.Hostname()

		for _, allowedDomain := range p.whitelistDomains {
			allowedHost, allowedPort := splitHostPort(allowedDomain)
			if allowedHost == "" {
				continue
			}

			if redirectHostname == strings.TrimPrefix(allowedHost, ".") ||
				(strings.HasPrefix(allowedHost, ".") &&
					strings.HasSuffix(redirectHostname, allowedHost)) {
				// the domain names match, now validate the ports
				// if the whitelisted domain's port is '*', allow all ports
				// if the whitelisted domain contains a specific port, only allow that port
				// if the whitelisted domain doesn't contain a port at all, only allow empty redirect ports ie http and https
				redirectPort := redirectURL.Port()
				if allowedPort == "*" ||
					allowedPort == redirectPort ||
					(allowedPort == "" && redirectPort == "") {
					return true
				}
			}
		}

		logger.Printf("Rejecting invalid redirect %q: domain / port not in whitelist", redirect)
		return false
	default:
		logger.Printf("Rejecting invalid redirect %q: not an absolute or relative URL", redirect)
		return false
	}
}

func (p *OAuthProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.preAuthChain.Then(http.HandlerFunc(p.serveHTTP)).ServeHTTP(rw, req)
}

func (p *OAuthProxy) serveHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != p.AuthOnlyPath && strings.HasPrefix(req.URL.Path, p.ProxyPrefix) {
		prepareNoCache(rw)
	}

	ctx := context.WithValue(req.Context(), constants.ContextTokenAuthPath{},
		p.provider.Data().RedeemURL.Path)
	req = req.Clone(ctx)

	switch path := req.URL.Path; {
	case path == p.RobotsPath:
		p.RobotsTxt(rw, req)
	case p.IsAllowedRequest(req):
		p.SkipAuthProxy(rw, req)
	case path == p.SignInPath:
		p.SignIn(rw, req)
	case path == p.SignOutPath:
		p.SignOut(rw, req)
	case path == p.OAuthStartPath:
		p.OAuthStart(rw, req)
	case path == p.OAuthCallbackPath:
		p.OAuthCallback(rw, req)
	case path == p.AuthOnlyPath:
		p.AuthOnly(rw, req)
	case path == p.UserInfoPath:
		p.UserInfo(rw, req)
	case path == p.provider.Data().LoginURL.Path: // Authorization Endpoint
		p.MockLoginRequest(rw, req)
	case path == p.provider.Data().RedeemURL.Path: // Token Endpoint
		p.MockTokenRequest(rw, req)
	case path == p.provider.Data().LogoutURL.Path: // Logout Endpoint
		p.MockLogoutRequest(rw, req)
	case path == p.provider.Data().JwksURL.Path: // JwksUri Endpoint
		p.MockJwksUriRequest(rw, req)
	case path == p.provider.Data().ChangePasswordURL.Path:
		p.MockChangePasswordUriRequest(rw, req)
	default:
		p.Proxy(rw, req)
	}
}

// RobotsTxt disallows scraping pages from the OAuthProxy
func (p *OAuthProxy) RobotsTxt(rw http.ResponseWriter, req *http.Request) {
	p.pageWriter.WriteRobotsTxt(rw, req)
}

// ErrorPage writes an error response
func (p *OAuthProxy) ErrorPage(rw http.ResponseWriter, req *http.Request, code int, appError string, messages ...interface{}) {
	redirectURL, err := p.getAppRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
	}
	if redirectURL == p.SignInPath || redirectURL == "" {
		redirectURL = "/"
	}

	scope := middlewareapi.GetRequestScope(req)
	p.pageWriter.WriteErrorPage(rw, pagewriter.ErrorPageOpts{
		Status:      code,
		RedirectURL: redirectURL,
		RequestID:   scope.RequestID,
		AppError:    appError,
		Messages:    messages,
	})
}

// IsAllowedRequest is used to check if auth should be skipped for this request
func (p *OAuthProxy) IsAllowedRequest(req *http.Request) bool {
	isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
	return isPreflightRequestAllowed || p.isAllowedRoute(req) || p.isTrustedIP(req)
}

// IsAllowedRoute is used to check if the request method & path is allowed without auth
func (p *OAuthProxy) isAllowedRoute(req *http.Request) bool {
	for _, route := range p.allowedRoutes {
		if (route.method == "" || req.Method == route.method) && route.pathRegex.MatchString(req.URL.Path) {
			return true
		}
	}
	return false
}

// isTrustedIP is used to check if a request comes from a trusted client IP address.
func (p *OAuthProxy) isTrustedIP(req *http.Request) bool {
	if p.trustedIPs == nil {
		return false
	}

	remoteAddr, err := ip.GetClientIP(p.realClientIPParser, req)
	if err != nil {
		logger.Errorf("Error obtaining real IP for trusted IP list: %v", err)
		// Possibly spoofed X-Real-IP header
		return false
	}

	if remoteAddr == nil {
		return false
	}

	return p.trustedIPs.Has(remoteAddr)
}

func (p *OAuthProxy) modifyRequestForMockLoginAPI(providerData *providers.ProviderData,
	req *http.Request) *http.Request {
	if req.Method == http.MethodGet {
		if err := req.ParseForm(); err != nil {
			logger.Errorf("Error parsing form data: %v", err)
			return req
		}

		req.Header.Add("X-Auth-Request-Redirect", req.FormValue("redirect_uri"))

		p.updateConfigToRequestScope(providerData, req)
	}
	return req
}

func (p *OAuthProxy) updateConfigToRequestScope(providerData *providers.ProviderData, req *http.Request) {
	clients := providerData.Clients[req.FormValue("client_id")]
	for _, clientConfigs := range clients {
		// making a copy for request scope
		config := make(map[string]string)
		for key, value := range clientConfigs {
			config[key] = value
		}

		configClientId, clientIdOk := config["client_id"]
		_, clientSecretOk := config["client_secret"]
		_, clientSecretFileOk := config["client_secret_file"]
		configRedirectUri, redirectUriOk := config["redirect_uri"]

		if clientIdOk && redirectUriOk && (clientSecretOk || clientSecretFileOk) &&
			configClientId != "" && configClientId == req.FormValue("client_id") &&
			req.FormValue("response_type") == "code" && configRedirectUri != "" {

			if req.FormValue("scope") != "" {
				config["scope"] = req.FormValue("scope")
			}
			if req.FormValue("acr_values") != "" {
				config["acr_values"] = req.FormValue("acr_values")
			}
			if req.FormValue("prompt") != "" {
				config["prompt"] = req.FormValue("prompt")
			}
			if req.FormValue("approval_prompt") != "" {
				config["approval_prompt"] = req.FormValue("approval_prompt")
			}

			if req.FormValue("kc_idp_hint") != "" {
				config["kc_idp_hint"] = req.FormValue("kc_idp_hint")
			}

			middlewareapi.GetRequestScope(req).RequestedClientConfig = config
			middlewareapi.GetRequestScope(req).RequestedClientVerifier = providerData.ClientsVerifiers[configClientId]
		}
	}
}

// Mock OIDC login API
func (p *OAuthProxy) MockLoginRequest(rw http.ResponseWriter, req *http.Request) {
	reqClientId := req.FormValue("client_id")
	reqRedirect := req.FormValue("redirect_uri")

	if !p.isValidClientId(reqClientId) {
		err := fmt.Sprintf("Error validating client_id %v", reqClientId)
		logger.Error(err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err)
		return
	}

	if !p.IsValidRedirect(reqRedirect) {
		err := fmt.Sprintf("Error validating redirect_uri %v", reqRedirect)
		logger.Error(err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err)
		return
	}
	req = p.modifyRequestForMockLoginAPI(p.provider.Data(), req)
	p.OAuthStart(rw, req)
}

// Mock Token API
func (p *OAuthProxy) MockTokenRequest(rw http.ResponseWriter, req *http.Request) {
	prepareNoCache(rw)

	rw.Header().Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), constants.ContextIsMockOauthTokenRequestCall{}, true)
	req = req.Clone(ctx)

	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			logger.Errorf("Error parsing form data: %v", err)
			return
		}

		if req.FormValue("grant_type") != "authorization_code" &&
			req.FormValue("grant_type") != "password" &&
			req.FormValue("grant_type") != "refresh_token" {
			rw.WriteHeader(http.StatusBadRequest)
		} else if req.FormValue("grant_type") == "authorization_code" {
			if req.FormValue("code") == "" {
				rw.WriteHeader(http.StatusBadRequest)
			} else {
				session, err := p.LoadCookiedSession(req)
				if err != nil {
					logger.Printf("Error loading oauth2 session: %v", err)
					logger.Printf("Trying code from request directly with provider")
					session, err = p.redeemCode(req)
					if err != nil {
						rw.WriteHeader(http.StatusNotFound)
						return
					}

				}
				tokenResponse := &authServerTokenResponse{
					TokenType:             session.TokenType,
					IDToken:               session.IDToken,
					RefreshToken:          session.RefreshToken,
					RefreshTokenExpiresIn: session.RefreshExpiresIn,
					AccessToken:           session.AccessToken,
					ExpiresIn:             session.AccessExpiresIn,
					Scope:                 session.Scope,
					SessionState:          session.SessionState,
				}

				err = json.NewEncoder(rw).Encode(tokenResponse)
				if err != nil {
					logger.Printf("Error encoding user info: %v", err)
					rw.WriteHeader(http.StatusInternalServerError)
					return
				}
				rw.WriteHeader(http.StatusOK)
			}
		} else if req.FormValue("grant_type") == "refresh_token" {
			if req.FormValue("client_id") == "" || req.FormValue("refresh_token") == "" {
				rw.WriteHeader(http.StatusBadRequest)
			} else {
				if !p.setRequestedClientConfigToRequestScope(req, "") {
					logger.Printf("Error refreshing session: Failed to set client configuration")
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				originalRefreshToken := req.FormValue("refresh_token")

				ctx := context.WithValue(req.Context(), constants.ContextSkipRefreshInterval{}, true)
				ctx = context.WithValue(ctx, constants.ContextOriginalRefreshToken{}, originalRefreshToken)

				req = req.Clone(ctx)

				session := &sessionsapi.SessionState{RefreshToken: originalRefreshToken}

				err := p.sessionLoader.RefreshSessionForcefully(rw, req, session)
				if err != nil {
					logger.Printf("Error refreshing session: %v", err)
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				tokenResponse := &authServerTokenResponse{
					TokenType:             session.TokenType,
					IDToken:               session.IDToken,
					RefreshToken:          session.RefreshToken,
					RefreshTokenExpiresIn: session.RefreshExpiresIn,
					AccessToken:           session.AccessToken,
					ExpiresIn:             session.AccessExpiresIn,
					Scope:                 session.Scope,
					SessionState:          session.SessionState,
				}

				err = json.NewEncoder(rw).Encode(tokenResponse)
				if err != nil {
					logger.Printf("Error encoding user info: %v", err)
					rw.WriteHeader(http.StatusInternalServerError)
					return
				}
				rw.WriteHeader(http.StatusOK)
			}
		} else if req.FormValue("grant_type") == "password" {
			if req.FormValue("client_id") == "" || req.FormValue("username") == "" ||
				req.FormValue("password") == "" {
				rw.WriteHeader(http.StatusBadRequest)
			} else {
				if !p.setRequestedClientConfigToRequestScope(req, "") {
					logger.Printf("Error granting access: Failed to set client configuration")
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				username := req.FormValue("username")
				password := req.FormValue("password")

				session, err := p.provider.PerformPasswordGrant(ctx, username, password)
				if session == nil || err != nil {
					logger.Printf("Error granting access: %v", err)
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				tokenResponse := &authServerTokenResponse{
					TokenType:             session.TokenType,
					RefreshToken:          session.RefreshToken,
					RefreshTokenExpiresIn: session.RefreshExpiresIn,
					AccessToken:           session.AccessToken,
					ExpiresIn:             session.AccessExpiresIn,
					Scope:                 session.Scope,
					SessionState:          session.SessionState,
				}

				err = json.NewEncoder(rw).Encode(tokenResponse)
				if err != nil {
					logger.Printf("Error encoding user info: %v", err)
					rw.WriteHeader(http.StatusInternalServerError)
					return
				}
				rw.WriteHeader(http.StatusOK)
			}
		}
	} else {
		rw.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (p *OAuthProxy) isValidClientId(reqClientId string) bool {
	clients := []string{p.provider.Data().ClientID}
	for clientId := range p.provider.Data().Clients {
		clients = append(clients, clientId)
	}

	for index := range clients {
		clientId := clients[index]
		if clientId == reqClientId {
			return true
		}
	}
	return false
}

// SignInPage writes the sing in template to the response
func (p *OAuthProxy) SignInPage(rw http.ResponseWriter, req *http.Request, code int) {
	prepareNoCache(rw)
	err := p.ClearSessionCookie(rw, req)
	if err != nil {
		logger.Printf("Error clearing session cookie: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	rw.WriteHeader(code)

	redirectURL, err := p.getAppRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	if redirectURL == p.SignInPath {
		redirectURL = "/"
	}

	p.pageWriter.WriteSignInPage(rw, req, redirectURL)
}

// ManualSignIn handles basic auth logins to the proxy
func (p *OAuthProxy) ManualSignIn(req *http.Request) (string, bool) {
	if req.Method != "POST" || p.basicAuthValidator == nil {
		return "", false
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false
	}
	// check auth
	if p.basicAuthValidator.Validate(user, passwd) {
		logger.PrintAuthf(user, req, logger.AuthSuccess, "Authenticated via HtpasswdFile")
		return user, true
	}
	logger.PrintAuthf(user, req, logger.AuthFailure, "Invalid authentication via HtpasswdFile")
	return "", false
}

// SignIn serves a page prompting users to sign in
func (p *OAuthProxy) SignIn(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.getAppRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	user, ok := p.ManualSignIn(req)
	if ok {
		session := &sessionsapi.SessionState{User: user}
		_, err := p.SaveSession(rw, req, session)
		if err != nil {
			logger.Printf("Error saving session: %v", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			return
		}
		http.Redirect(rw, req, redirect, http.StatusFound)
	} else {
		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusOK)
		}
	}
}

// UserInfo endpoint outputs session email and preferred username in JSON format
func (p *OAuthProxy) UserInfo(rw http.ResponseWriter, req *http.Request) {

	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	userInfo := struct {
		User              string   `json:"user"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups,omitempty"`
		PreferredUsername string   `json:"preferredUsername,omitempty"`
	}{
		User:              session.User,
		Email:             session.Email,
		Groups:            session.Groups,
		PreferredUsername: session.PreferredUsername,
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	err = json.NewEncoder(rw).Encode(userInfo)
	if err != nil {
		logger.Printf("Error encoding user info: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	}
}

func (p *OAuthProxy) MockLogoutRequest(rw http.ResponseWriter, req *http.Request) {
	var redirectURI string

	if req.FormValue("redirect_uri") != "" {
		redirectURI = req.FormValue("redirect_uri")
		if !p.IsValidRedirect(redirectURI) {
			logger.Printf("Logout redirect uri is invalid")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	if req.Method == "POST" && req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if req.FormValue("refresh_token") == "" {
			err := errors.New("refresh_token not provided")
			logger.Errorf("Error logging out: %v", err)
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if req.FormValue("client_id") == "" {
			err := errors.New("client_id not provided")
			logger.Errorf("Error logging out: %v", err)
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		var ss *sessionsapi.SessionState = &sessionsapi.SessionState{
			ClientId:     req.FormValue("client_id"),
			RefreshToken: req.FormValue("refresh_token"),
		}

		_, err := p.provider.Logout(req.Context(), ss)
		if err != nil {
			logger.Errorf("Error logging out: %v", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		logoutUrl := p.provider.Data().LogoutURL
		scheme := req.URL.Scheme
		host := req.URL.Host
		if scheme == "" {
			scheme = "https"
		}
		if host == "" {
			host = req.Host
		}
		urlHost := fmt.Sprintf("%s://%s", scheme, host)

		var rdUrl string
		if redirectURI != "" {
			rdUrl = urlHost + p.SignOutPath + "?rd=" + redirectURI
		} else {
			rdUrl = urlHost + p.SignOutPath + "?rd=" + urlHost + p.SignInPath
		}

		queries := logoutUrl.Query()
		queries.Set("redirect_uri", rdUrl)
		logoutUrl.RawQuery = queries.Encode()

		logger.Errorf("Redirect URL: %v", logoutUrl)

		http.Redirect(rw, req, logoutUrl.String(), http.StatusFound)
	}
}

func (p *OAuthProxy) MockJwksUriRequest(rw http.ResponseWriter, req *http.Request) {
	prepareNoCache(rw)

	c := http.Client{}
	resp, err := c.Get(p.provider.Data().JwksURL.String())

	if err != nil {
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	rw.Header().Add("Content-Type", "application/json")
	rw.Write(body)
}

func (p *OAuthProxy) MockChangePasswordUriRequest(rw http.ResponseWriter, req *http.Request) {
	http.Redirect(rw, req, p.provider.Data().ChangePasswordURL.String(), http.StatusFound)
}

// SignOut sends a response to clear the authentication cookie
func (p *OAuthProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.getAppRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	err = p.ClearSessionCookie(rw, req)
	if err != nil {
		logger.Errorf("Error clearing session cookie: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(rw, req, redirect, http.StatusFound)
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	prepareNoCache(rw)

	csrf, err := cookies.NewCSRF(p.CookieOptions)
	if err != nil {
		logger.Errorf("Error creating CSRF nonce: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	appRedirect, err := p.getAppRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining application redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	clientId, err := p.getClientID(req)
	if err != nil {
		logger.Printf("Error obtaining client ID from request: %v", err)
		logger.Printf("Setting default client ID")
		clientId = p.provider.Data().ClientID
	}

	clientIdBytes := []byte(clientId)

	// Hashing the clientIdBytes with the default cost of 10
	hashedClientIdBytes, err := bcrypt.GenerateFromPassword(clientIdBytes, bcrypt.DefaultCost)
	if err != nil {
		logger.Errorf("Error processing client id: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	callbackRedirect := p.getOAuthRedirectURI(req)
	loginURL := p.provider.GetLoginURL(
		req.Context(),
		callbackRedirect,
		encodeState(csrf.HashOAuthState(), appRedirect, string(hashedClientIdBytes)),
		csrf.HashOIDCNonce(),
	)

	if _, err := csrf.SetCookie(rw, req); err != nil {
		logger.Errorf("Error setting CSRF cookie: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	http.Redirect(rw, req, loginURL, http.StatusFound)
}

// OAuthCallback is the OAuth2 authentication flow callback that finishes the
// OAuth2 authentication flow
func (p *OAuthProxy) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	remoteAddr := ip.GetClientString(p.realClientIPParser, req, true)

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		logger.Errorf("Error while parsing OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		logger.Errorf("Error while parsing OAuth2 callback: %s", errorString)
		message := fmt.Sprintf("Login Failed: The upstream identity provider returned an error: %s", errorString)
		// Set the debug message and override the non debug message to be the same for this case
		p.ErrorPage(rw, req, http.StatusForbidden, message, message)
		return
	}

	nonce, appRedirect, hashedClientId, decodeErr := decodeState(req)

	if !p.setRequestedClientConfigToRequestScope(req, hashedClientId) {
		logger.Errorf("Error redeeming code during OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	session, err := p.redeemCode(req)
	if err != nil {
		logger.Errorf("Error redeeming code during OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	err = p.enrichSessionState(req.Context(), session)
	if err != nil {
		logger.Errorf("Error creating session during OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	csrf, err := cookies.LoadCSRFCookie(req, p.CookieOptions)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unable to obtain CSRF cookie")
		p.ErrorPage(rw, req, http.StatusForbidden, err.Error(), "Login Failed: Unable to find a valid CSRF token. Please try again.")
		return
	}

	csrf.ClearCookie(rw, req)

	if decodeErr != nil {
		logger.Errorf("Error while parsing OAuth2 state: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	if !csrf.CheckOAuthState(nonce) {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: CSRF token mismatch, potential attack")
		p.ErrorPage(rw, req, http.StatusForbidden, "CSRF token mismatch, potential attack", "Login Failed: Unable to find a valid CSRF token. Please try again.")
		return
	}

	csrf.SetSessionNonce(session)
	p.provider.ValidateSession(req.Context(), session)

	if !p.IsValidRedirect(appRedirect) {
		appRedirect = p.defaultAppRedirectURL.String()
	}

	// set cookie, or deny
	authorized, err := p.provider.Authorize(req.Context(), session)
	if err != nil {
		logger.Errorf("Error with authorization: %v", err)
	}
	if p.Validator(session.Email) && authorized {
		logger.PrintAuthf(session.Email, req, logger.AuthSuccess, "Authenticated via OAuth2: %s", session)
		ticketID, err := p.SaveSession(rw, req, session)
		if err != nil {
			logger.Errorf("Error saving session state for %s: %v", remoteAddr, err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			return
		}
		if ticketID != "" {
			req, err := http.NewRequest("GET", appRedirect, nil)
			if err != nil {
				logger.Errorf("Error appending code to app redirect URL: %v", err)
				p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			}
			q := req.URL.Query()
			q.Add("code", ticketID)
			if session.SessionState != "" {
				q.Add("session_state", session.SessionState)
			}
			req.URL.RawQuery = q.Encode()
			appRedirect = req.URL.String()
		}
		http.Redirect(rw, req, appRedirect, http.StatusFound)
	} else {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unauthorized")
		p.ErrorPage(rw, req, http.StatusForbidden, "Invalid session: unauthorized")
	}
}

func (p *OAuthProxy) setRequestedClientConfigToRequestScope(req *http.Request, hashedClientId string) bool {
	var clients []map[string]string
	var clientId string
	if hashedClientId != "" {
		decryptedClientId, err := p.getValidatedClientId(hashedClientId, req)
		clientId = decryptedClientId
		if err != nil {
			return false
		}
		clients = p.provider.Data().Clients[clientId]
	} else {
		clientId = req.FormValue("client_id")
		clients = p.provider.Data().Clients[clientId]
	}

	if len(clients) == 0 {
		return true
	}
	for _, clientConfigs := range clients {
		// making a copy for request scope
		config := make(map[string]string)
		for key, value := range clientConfigs {
			config[key] = value
		}

		/* configClientId, clientIdOk := config["client_id"]
		if clientIdOk && configClientId != "" && configClientId == clientId {
			middlewareapi.GetRequestScope(req).RequestedClientConfig = config
			middlewareapi.GetRequestScope(req).RequestedClientVerifier = p.provider.Data().ClientsVerifiers[configClientId]
			return true
		} */

		configClientId, clientIdOk := config["client_id"]
		_, clientSecretOk := config["client_secret"]
		_, clientSecretFileOk := config["client_secret_file"]

		if clientIdOk && (clientSecretOk || clientSecretFileOk) &&
			configClientId != "" && configClientId == clientId {
			middlewareapi.GetRequestScope(req).RequestedClientConfig = config
			middlewareapi.GetRequestScope(req).RequestedClientVerifier = p.provider.Data().ClientsVerifiers[configClientId]
			return true
		}
	}
	return false
}

func (p *OAuthProxy) getClientID(req *http.Request) (string, error) {
	clientID := req.Form.Get("client_id")
	if clientID == "" {
		return "", errors.New("missing client_id in the request parameters")
	}
	return clientID, nil
}

func (p *OAuthProxy) getSessionChain() alice.Chain {
	return p.sessionChain
}

func (p *OAuthProxy) redeemCode(req *http.Request) (*sessionsapi.SessionState, error) {
	code := req.Form.Get("code")
	if code == "" {
		return nil, providers.ErrMissingCode
	}

	redirectURI := p.getOAuthRedirectURI(req)
	ctx := req.Context()
	s, err := p.provider.Redeem(ctx, redirectURI, code)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (p *OAuthProxy) enrichSessionState(ctx context.Context, s *sessionsapi.SessionState) error {
	var err error
	if s.Email == "" {
		// TODO(@NickMeves): Remove once all provider are updated to implement EnrichSession
		// nolint:staticcheck
		s.Email, err = p.provider.GetEmailAddress(ctx, s)
		if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
			return err
		}
	}

	return p.provider.EnrichSession(ctx, s)
}

// AuthOnly checks whether the user is currently logged in (both authentication
// and optional authorization).
func (p *OAuthProxy) AuthOnly(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Unauthorized cases need to return 403 to prevent infinite redirects with
	// subrequest architectures
	if !authOnlyAuthorize(req, session) {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// we are authenticated
	p.addHeadersForProxying(rw, session)
	p.headersChain.Then(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rw, req)
}

// SkipAuthProxy proxies allowlisted requests and skips authentication
func (p *OAuthProxy) SkipAuthProxy(rw http.ResponseWriter, req *http.Request) {
	p.headersChain.Then(p.serveMux).ServeHTTP(rw, req)
}

// Proxy proxies the user request if the user is authenticated else it prompts
// them to authenticate
func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	switch err {
	case nil:
		// we are authenticated
		p.addHeadersForProxying(rw, session)
		p.headersChain.Then(p.serveMux).ServeHTTP(rw, req)
	case ErrNeedsLogin:
		// we need to send the user to a login screen
		if isAjax(req) {
			// no point redirecting an AJAX request
			p.errorJSON(rw, http.StatusUnauthorized)
			return
		}

		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusForbidden)
		}

	case ErrAccessDenied:
		p.ErrorPage(rw, req, http.StatusForbidden, "The session failed authorization checks")

	default:
		// unknown error
		logger.Errorf("Unexpected internal error: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	}
}

// See https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching?hl=en
var noCacheHeaders = map[string]string{
	"Expires":         time.Unix(0, 0).Format(time.RFC1123),
	"Cache-Control":   "no-cache, no-store, must-revalidate, max-age=0",
	"X-Accel-Expires": "0", // https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/
}

// prepareNoCache prepares headers for preventing browser caching.
func prepareNoCache(w http.ResponseWriter) {
	// Set NoCache headers
	for k, v := range noCacheHeaders {
		w.Header().Set(k, v)
	}
}

// getOAuthRedirectURI returns the redirectURL that the upstream OAuth Provider will
// redirect clients to once authenticated.
// This is usually the OAuthProxy callback URL.
func (p *OAuthProxy) getOAuthRedirectURI(req *http.Request) string {
	// if `p.redirectURL` already has a host, return it
	if p.redirectURL.Host != "" {
		return p.redirectURL.String()
	}

	// Otherwise figure out the scheme + host from the request
	rd := *p.redirectURL
	rd.Host = requestutil.GetRequestHost(req)
	rd.Scheme = requestutil.GetRequestProto(req)

	// If there's no scheme in the request, we should still include one
	if rd.Scheme == "" {
		rd.Scheme = schemeHTTP
	}

	// If CookieSecure is true, return `https` no matter what
	// Not all reverse proxies set X-Forwarded-Proto
	if p.CookieOptions.Secure {
		rd.Scheme = schemeHTTPS
	}
	return rd.String()
}

// getAppRedirect determines the full URL or URI path to redirect clients to
// once authenticated with the OAuthProxy
// Strategy priority (first legal result is used):
// - `rd` querysting parameter
// - `X-Auth-Request-Redirect` header
// - `X-Forwarded-(Proto|Host|Uri)` headers (when ReverseProxy mode is enabled)
// - `X-Forwarded-(Proto|Host)` if `Uri` has the ProxyPath (i.e. /oauth2/*)
// - `X-Forwarded-Uri` direct URI path (when ReverseProxy mode is enabled)
// - `req.URL.RequestURI` if not under the ProxyPath (i.e. /oauth2/*)
// - `/`
func (p *OAuthProxy) getAppRedirect(req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", err
	}

	// These redirect getter functions are strategies ordered by priority
	// for figuring out the redirect URL.
	type redirectGetter func(req *http.Request) string
	for _, rdGetter := range []redirectGetter{
		p.getRdQuerystringRedirect,
		p.getXAuthRequestRedirect,
		p.getXForwardedHeadersRedirect,
		p.getURIRedirect,
	} {
		redirect := rdGetter(req)
		// Call `p.IsValidRedirect` again here a final time to be safe
		if redirect != "" && p.IsValidRedirect(redirect) {
			return redirect, nil
		}
	}

	return p.defaultAppRedirectURL.String(), nil
}

func isForwardedRequest(req *http.Request) bool {
	return requestutil.IsProxied(req) &&
		req.Host != requestutil.GetRequestHost(req)
}

func (p *OAuthProxy) hasProxyPrefix(path string) bool {
	return strings.HasPrefix(path, fmt.Sprintf("%s/", p.ProxyPrefix))
}

func (p *OAuthProxy) hasMockPrefix(path string) bool {
	return strings.HasPrefix(path, fmt.Sprintf("%s/", "/auth")) //TODO: Make it available in Options
}

func (p *OAuthProxy) validateRedirect(redirect string, errorFormat string) string {
	if p.IsValidRedirect(redirect) {
		return redirect
	}
	if redirect != "" {
		logger.Errorf(errorFormat, redirect)
	}
	return ""
}

// getRdQuerystringRedirect handles this getAppRedirect strategy:
// - `rd` querysting parameter
func (p *OAuthProxy) getRdQuerystringRedirect(req *http.Request) string {
	return p.validateRedirect(
		req.Form.Get("rd"),
		"Invalid redirect provided in rd querystring parameter: %s",
	)
}

// getXAuthRequestRedirect handles this getAppRedirect strategy:
// - `X-Auth-Request-Redirect` Header
func (p *OAuthProxy) getXAuthRequestRedirect(req *http.Request) string {
	return p.validateRedirect(
		req.Header.Get("X-Auth-Request-Redirect"),
		"Invalid redirect provided in X-Auth-Request-Redirect header: %s",
	)
}

// getXForwardedHeadersRedirect handles these getAppRedirect strategies:
// - `X-Forwarded-(Proto|Host|Uri)` headers (when ReverseProxy mode is enabled)
// - `X-Forwarded-(Proto|Host)` if `Uri` has the ProxyPath (i.e. /oauth2/*)
func (p *OAuthProxy) getXForwardedHeadersRedirect(req *http.Request) string {
	if !isForwardedRequest(req) {
		return ""
	}

	uri := requestutil.GetRequestURI(req)
	if p.hasProxyPrefix(uri) {
		uri = "/"
	}
	if p.hasMockPrefix(uri) {
		uri = "/"
	}

	redirect := fmt.Sprintf(
		"%s://%s%s",
		requestutil.GetRequestProto(req),
		requestutil.GetRequestHost(req),
		uri,
	)

	return p.validateRedirect(redirect,
		"Invalid redirect generated from X-Forwarded-* headers: %s")
}

// getURIRedirect handles these getAppRedirect strategies:
// - `X-Forwarded-Uri` direct URI path (when ReverseProxy mode is enabled)
// - `req.URL.RequestURI` if not under the ProxyPath (i.e. /oauth2/*)
// - `req.URL.RequestURI` if not under the MockPath (i.e. /auth/*)
// - `/`
func (p *OAuthProxy) getURIRedirect(req *http.Request) string {
	redirect := p.validateRedirect(
		requestutil.GetRequestURI(req),
		"Invalid redirect generated from X-Forwarded-Uri header: %s",
	)
	if redirect == "" {
		redirect = req.URL.RequestURI()
	}

	if redirect == "/" {
		return p.defaultAppRedirectURL.String()
	}

	if p.hasProxyPrefix(redirect) {
		return p.defaultAppRedirectURL.String()
	}

	if p.hasMockPrefix(redirect) {
		return p.defaultAppRedirectURL.String()
	}
	return redirect
}

// splitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
// *** taken from net/url, modified validOptionalPort() to accept ":*"
func splitHostPort(hostport string) (host, port string) {
	return requestutil.SplitHostPort(hostport)
}

// getAuthenticatedSession checks whether a user is authenticated and returns a session object and nil error if so
// Returns:
// - `nil, ErrNeedsLogin` if user needs to login.
// - `nil, ErrAccessDenied` if the authenticated user is not authorized
// Set-Cookie headers may be set on the response as a side-effect of calling this method.
func (p *OAuthProxy) getAuthenticatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	var session *sessionsapi.SessionState

	getSession := p.sessionChain.Then(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session = middlewareapi.GetRequestScope(req).Session
	}))
	getSession.ServeHTTP(rw, req)

	if session == nil {
		return nil, ErrNeedsLogin
	}

	invalidEmail := session.Email != "" && !p.Validator(session.Email)
	authorized, err := p.provider.Authorize(req.Context(), session)
	if err != nil {
		logger.Errorf("Error with authorization: %v", err)
	}

	if invalidEmail || !authorized {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authorization via session: removing session %s", session)
		// Invalid session, clear it
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			logger.Errorf("Error clearing session cookie: %v", err)
		}
		return nil, ErrAccessDenied
	}

	return session, nil
}

func (p *OAuthProxy) getValidatedClientId(hashedClientId string, req *http.Request) (string, error) {
	clients := []string{p.provider.Data().ClientID}
	for clientId := range p.provider.Data().Clients {
		clients = append(clients, clientId)
	}

	for index := range clients {
		clientId := clients[index]
		err := bcrypt.CompareHashAndPassword([]byte(hashedClientId), []byte(clientId))
		if err == nil {
			return clientId, err
		}
	}
	return "", errors.New("provided client ID did not match with any configured client IDs")

}

// authOnlyAuthorize handles special authorization logic that is only done
// on the AuthOnly endpoint for use with Nginx subrequest architectures.
//
// TODO (@NickMeves): This method is a placeholder to be extended but currently
// fails the linter. Remove the nolint when functionality expands.
//
//nolint:gosimple
func authOnlyAuthorize(req *http.Request, s *sessionsapi.SessionState) bool {
	// Allow secondary group restrictions based on the `allowed_groups`
	// querystring parameter
	if !checkAllowedGroups(req, s) {
		return false
	}

	return true
}

func checkAllowedGroups(req *http.Request, s *sessionsapi.SessionState) bool {
	allowedGroups := extractAllowedGroups(req)
	if len(allowedGroups) == 0 {
		return true
	}

	for _, group := range s.Groups {
		if _, ok := allowedGroups[group]; ok {
			return true
		}
	}

	return false
}

func extractAllowedGroups(req *http.Request) map[string]struct{} {
	groups := map[string]struct{}{}

	query := req.URL.Query()
	for _, allowedGroups := range query["allowed_groups"] {
		for _, group := range strings.Split(allowedGroups, ",") {
			if group != "" {
				groups[group] = struct{}{}
			}
		}
	}

	return groups
}

// encodedState builds the OAuth state param out of our nonce,
// original application redirect, requested client id
func encodeState(nonce string, redirect string, clientId string) string {
	endodedRedirectURL := b64.RawURLEncoding.EncodeToString([]byte(redirect))
	endodedClientId := b64.RawURLEncoding.EncodeToString([]byte(clientId))
	plain := fmt.Sprintf("%v:%v:%v", nonce, endodedRedirectURL, endodedClientId)
	base64Plain := b64.RawURLEncoding.EncodeToString([]byte(plain))
	return base64Plain
}

// decodeState splits the reflected OAuth state response back into
// the nonce, original application redirect, requested client id
func decodeState(req *http.Request) (string, string, string, error) {
	base64State := req.Form.Get("state")
	sDec, _ := b64.RawURLEncoding.DecodeString(base64State)
	state := strings.SplitN(string(sDec), ":", 3)
	if len(state) != 3 {
		return "", "", "", errors.New("invalid length")
	}
	nonce := state[0]
	decodedRedirectURL, err := b64.RawURLEncoding.DecodeString(state[1])
	if err != nil {
		return "", "", "", err
	}
	decodedClientId, err := b64.RawURLEncoding.DecodeString(state[2])
	if err != nil {
		return "", "", "", err
	}
	return nonce, string(decodedRedirectURL), string(decodedClientId), nil
}

// addHeadersForProxying adds the appropriate headers the request / response for proxying
func (p *OAuthProxy) addHeadersForProxying(rw http.ResponseWriter, session *sessionsapi.SessionState) {
	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
	}
}

// isAjax checks if a request is an ajax request
func isAjax(req *http.Request) bool {
	acceptValues := req.Header.Values("Accept")
	const ajaxReq = applicationJSON
	// Iterate over multiple Accept headers, i.e.
	// Accept: application/json
	// Accept: text/plain
	for _, mimeTypes := range acceptValues {
		// Iterate over multiple mimetypes in a single header, i.e.
		// Accept: application/json, text/plain, */*
		for _, mimeType := range strings.Split(mimeTypes, ",") {
			mimeType = strings.TrimSpace(mimeType)
			if mimeType == ajaxReq {
				return true
			}
		}
	}
	return false
}

// errorJSON returns the error code with an application/json mime type
func (p *OAuthProxy) errorJSON(rw http.ResponseWriter, code int) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(code)
}
