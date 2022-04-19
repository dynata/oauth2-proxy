package providers

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/constants"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	auth "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	pe_jwt "github.com/researchnow/pe-go-lib/jwt"
	"golang.org/x/oauth2"
)

type KeycloakProvider struct {
	*ProviderData
	SkipNonce    bool
	TokenBuilder *auth.TokenBuilder
}

var _ Provider = (*KeycloakProvider)(nil)

// NewKeycloakProvider creates a KeyCloakProvider using the passed ProviderData
func NewKeycloakProvider(p *ProviderData) *KeycloakProvider {
	if p.ProfileURL == nil || p.ProfileURL.Host == "" {
		lastInd := strings.LastIndex(p.RedeemURL.Path, "/")
		keycloakDefaultProfileURL := &url.URL{
			Scheme: p.RedeemURL.Scheme,
			Host:   p.RedeemURL.Host,
			Path:   p.RedeemURL.Path[:lastInd] + "/userinfo",
		}
		keycloakDefaultLogoutURL := &url.URL{
			Scheme: p.RedeemURL.Scheme,
			Host:   p.RedeemURL.Host,
			Path:   p.RedeemURL.Path[:lastInd] + "/logout",
		}
		keycloakDefaultJwksURL := &url.URL{
			Scheme: p.RedeemURL.Scheme,
			Host:   p.RedeemURL.Host,
			Path:   p.RedeemURL.Path[:lastInd] + "/certs",
		}
		/* keycloakDefaultValidateURL := &url.URL{
			Scheme: p.RedeemURL.Scheme,
			Host:   p.RedeemURL.Host,
			Path:   p.RedeemURL.Path + "/introspect",
		} */
		p.setProviderDefaults(providerDefaults{
			// name:        keycloakProviderName,
			// loginURL:    keycloakDefaultLoginURL,
			// redeemURL:   keycloakDefaultRedeemURL,
			profileURL: keycloakDefaultProfileURL,
			// validateURL: keycloakDefaultValidateURL,
			// scope:       keycloakDefaultScope,
			logoutURL: keycloakDefaultLogoutURL,
			jwksURL:   keycloakDefaultJwksURL,
		})
	}
	p.ChangePasswordURL = &url.URL{
		Scheme: p.IssuerURL.Scheme,
		Host:   p.IssuerURL.Host,
		Path:   p.IssuerURL.Path + "/account/password",
	}

	return &KeycloakProvider{
		ProviderData: p,
		SkipNonce:    true,
	}
}

// EnrichSession uses the Keycloak userinfo endpoint to populate the session's
// email and groups.
func (p *KeycloakProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	groups, err := json.Get("groups").StringArray()
	if err == nil {
		for _, group := range groups {
			if group != "" {
				s.Groups = append(s.Groups, group)
			}
		}
	}

	email, err := json.Get("email").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	return nil
}

// GetLoginURL makes the LoginURL with optional nonce support
func (p *KeycloakProvider) GetLoginURL(ctx context.Context, redirectURI, state, nonce string) string {
	extraParams := url.Values{}
	if !p.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	loginURL := makeLoginURL(ctx, p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *KeycloakProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	clientId := p.ClientID

	clientId, clientSecret = getClientIdAndSecret(ctx, clientId, clientSecret)

	c := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	ss, err := p.createSession(ctx, token, false, false)

	if ss != nil {
		ss.ClientId = clientId
	}

	return ss, err
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
/* func (p *KeycloakProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if p.ProfileURL.String() == "" {
		if s.Email == "" {
			return errors.New("id_token did not contain an email and profileURL is not defined")
		}
		return nil
	}

	// Try to get missing emails or groups from a profileURL
	if s.Email == "" || s.Groups == nil {
		err := p.enrichFromProfileURL(ctx, s)
		if err != nil {
			logger.Errorf("Warning: Profile URL request failed: %v", err)
		}
	}

	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
} */

// enrichFromProfileURL enriches a session's Email & Groups via the JSON response of
// an OIDC profile URL
/* func (p *KeycloakProvider) enrichFromProfileURL(ctx context.Context, s *sessions.SessionState) error {
	respJSON, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return err
	}

	email, err := respJSON.Get(p.EmailClaim).String()
	if err == nil && s.Email == "" {
		s.Email = email
	}

	if len(s.Groups) > 0 {
		return nil
	}
	for _, group := range coerceArray(respJSON, p.GroupsClaim) {
		formatted, err := formatGroup(group)
		if err != nil {
			logger.Errorf("Warning: unable to format group of type %s with error %s",
				reflect.TypeOf(group), err)
			continue
		}
		s.Groups = append(s.Groups, formatted)
	}

	return nil
} */

// ValidateSession checks that the session's IDToken is still valid
func (p *KeycloakProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	//isTokenValid := validateKeycloakToken(ctx, p, s, nil)
	isTokenValid := true // skiping introspection during validation
	verifier := p.Verifier

	verifier = getClientVerifier(ctx, verifier)

	idToken, err := verifier.Verify(ctx, s.IDToken)
	if err != nil {
		logger.Errorf("id_token verification failed: %v", err)
		return false
	}

	if p.SkipNonce {
		return true && isTokenValid
	}
	err = p.checkNonce(s, idToken)
	if err != nil {
		logger.Errorf("nonce verification failed: %v", err)
		return false
	}

	return true && isTokenValid
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access Token (and optional ID token) if required
func (p *KeycloakProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	skipRefreshInterval := ctx.Value(constants.ContextSkipRefreshInterval{})
	performSkip := skipRefreshInterval != nil && skipRefreshInterval.(bool)

	if s == nil ||
		(!performSkip && s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) ||
		s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed session: %s", s)
	return true, nil
}

// redeemRefreshToken uses a RefreshToken with the RedeemURL to refresh the
// Access Token and (probably) the ID Token.
func (p *KeycloakProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	clientId := p.ClientID

	if s.ClientId != "" {
		clientId = s.ClientId
		clientConfigs := p.Clients[clientId]
		for _, client := range clientConfigs {
			if client["client_id"] != "" && client["client_secret"] != "" {
				clientId = client["client_id"]
				clientSecret = client["client_secret"]
				break
			}
		}
	} else if ctx != nil {
		clientId, clientSecret = getClientIdAndSecret(ctx, clientId, clientSecret)
	}

	c := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}

	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	newSession, err := p.createSession(ctx, token, true, false)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the
	// session will not contain an id token.
	// If it doesn't it's probably better to retain the old one
	if newSession.IDToken != "" {
		s.IDToken = newSession.IDToken
		s.Email = newSession.Email
		s.User = newSession.User
		s.Groups = newSession.Groups
		s.PreferredUsername = newSession.PreferredUsername
	}

	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	s.AccessExpiresIn = newSession.AccessExpiresIn
	s.RefreshExpiresIn = newSession.RefreshExpiresIn
	s.TokenType = newSession.TokenType
	s.Scope = newSession.Scope
	s.SessionState = newSession.SessionState
	s.ClientId = clientId

	return nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *KeycloakProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	verifier := p.Verifier

	verifier = getClientVerifier(ctx, verifier)

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	ss, err := p.buildSessionFromClaims(idToken)
	if err != nil {
		return nil, err
	}

	// Allow empty Email in Bearer case since we can't hit the ProfileURL
	if ss.Email == "" {
		ss.Email = ss.User
	}

	ss.AccessToken = token
	ss.IDToken = token
	ss.RefreshToken = ""
	ss.ExpiresOn = &idToken.Expiry

	return ss, nil
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *KeycloakProvider) createSession(ctx context.Context, token *oauth2.Token, refresh, passwordGrant bool) (*sessions.SessionState, error) {
	idToken, err := p.verifyIDToken(ctx, token)
	if err != nil {
		switch err {
		case ErrMissingIDToken:
			// IDToken is mandatory in Redeem but optional in Refresh
			if !refresh && !passwordGrant {
				return nil, errors.New("token response did not contain an id_token")
			}
		default:
			return nil, fmt.Errorf("could not verify id_token: %v", err)
		}
	}

	ss, err := p.buildSessionFromClaims(idToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken
	ss.IDToken = getIDToken(token)

	created := time.Now()
	ss.CreatedAt = &created
	ss.ExpiresOn = &token.Expiry

	if token.Extra("expires_in") != nil {
		ss.AccessExpiresIn = token.Extra("expires_in").(float64)
	}
	if token.Extra("refresh_expires_in") != nil {
		ss.RefreshExpiresIn = token.Extra("refresh_expires_in").(float64)
	}
	if token.Type() != "" {
		ss.TokenType = token.Type()
	}
	if token.Extra("scope") != nil {
		ss.Scope = token.Extra("scope").(string)
	}
	if token.Extra("session_state") != nil {
		ss.SessionState = token.Extra("session_state").(string)
	}

	return ss, nil
}

func (p *KeycloakProvider) Logout(ctx context.Context, s *sessions.SessionState) (bool, error) {
	providerData := p.Data()

	logoutURL := providerData.LogoutURL
	if s != nil && logoutURL != nil && logoutURL.String() != "" {
		clientId := providerData.ClientID
		clientSecret, err := providerData.GetClientSecret()

		if err != nil {
			return false, err
		}

		if s.ClientId != "" {
			clientId = s.ClientId
		}
		refreshToken := s.RefreshToken

		configMapList := providerData.Clients[clientId]
		for _, config := range configMapList {
			if config["client_id"] == clientId {
				clientSecret, err = GetClientSecret(config["client_secret"], config["client_secret_file"])
				if err != nil {
					return false, err
				}
			}
		}

		httpClient := http.Client{}

		form := url.Values{}
		form.Add("client_id", clientId)
		form.Add("client_secret", clientSecret)
		form.Add("refresh_token", refreshToken)

		newRequest, err := http.NewRequest("POST", providerData.LogoutURL.String(), strings.NewReader(form.Encode()))
		newRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			return false, err
		}

		resp, err := httpClient.Do(newRequest)
		if err != nil {
			return false, err
		}
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			logger.Print("Logged out from provider")
			return true, nil
		}
	}
	return false, nil
}

func (p *KeycloakProvider) PerformPasswordGrant(ctx context.Context, username, password string) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	clientId := p.ClientID

	clientId, clientSecret = getClientIdAndSecret(ctx, clientId, clientSecret)

	c := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	token, err := c.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	ss, err := p.createSession(ctx, token, false, true)

	if ss != nil {
		ss.ClientId = clientId
	}

	return ss, err
}

// SetUsers configures allowed usernames
func (p *KeycloakProvider) MakeTokenBuilder(hmacSecretKeyPath string, rsaPrivateKeyPath string) error {
	//
	jwkKeyFinder, err := pe_jwt.NewSimpleJWKFinder(p.JwksURL.String())
	if err != nil {
		//log.Fatal("Invalid JWK url provided")
		return err
	}

	hmacSecretFileContent, err := ioutil.ReadFile(hmacSecretKeyPath)
	if err != nil {
		return err
	}
	content := string(hmacSecretFileContent)
	contentTrimmed := strings.TrimSuffix(content, "\n")
	hmacSecret, err := hex.DecodeString(contentTrimmed)
	if err != nil {
		return err
	}
	// hmacSecret := make([]byte, hex.DecodedLen(len(hmacSecretHex)))
	// _, err = hex.Decode(hmacSecret, hmacSecretHex)
	// if err != nil {
	// 	log.Fatal("hmax secret issue")
	// 	return nil
	// }

	signBytes, err := ioutil.ReadFile(rsaPrivateKeyPath)
	if err != nil {
		//log.Fatal("RSA private file not found")
		return err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		//log.Fatal("RSA private file parsing issue")
		return err
	}

	p.TokenBuilder = auth.NewTokenBuilder(jwkKeyFinder, hmacSecret, signKey)

	return nil
}

// SetUsers configures allowed usernames
func (p *KeycloakProvider) MakeTokenBuilderFromKeys(hmacSecretKey string, rsaPrivateKey string) error {
	//
	jwkKeyFinder, err := pe_jwt.NewSimpleJWKFinder(p.JwksURL.String())
	if err != nil {
		return err
	}

	hmacSecret := []byte(hmacSecretKey)
	if err != nil {
		return err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKey))
	if err != nil {
		//log.Fatal("RSA private file parsing issue")
		return err
	}

	p.TokenBuilder = auth.NewTokenBuilder(jwkKeyFinder, hmacSecret, signKey)

	return nil
}

func validateKeycloakToken(ctx context.Context, p Provider, s *sessions.SessionState, header http.Header) bool {
	if s == nil || s.AccessToken == "" || p.Data().ValidateURL == nil || p.Data().ValidateURL.String() == "" {
		return false
	}

	if header == nil {
		header = http.Header{}
	}

	clientSecret, err := p.Data().GetClientSecret()
	if err != nil {
		panic("Failed to get client credentials during validation of keycloak token")
	}

	clientId := p.Data().ClientID

	if s.ClientId != "" {
		clientId = s.ClientId
		clientConfigs := p.Data().Clients[clientId]
		for _, client := range clientConfigs {
			if client["client_id"] != "" && client["client_secret"] != "" {
				clientId = client["client_id"]
				clientSecret = client["client_secret"]
				break
			}
		}
	} else if ctx != nil {
		clientId, clientSecret = getClientIdAndSecret(ctx, clientId, clientSecret)
	}
	auth := clientId + ":" + clientSecret

	header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	header.Set("Content-Type", "application/x-www-form-urlencoded")
	endpoint := p.Data().ValidateURL.String()
	form := url.Values{"token": {s.AccessToken}}

	result := requests.New(endpoint).
		WithContext(ctx).
		WithHeaders(header).
		WithMethod("POST").
		WithBody(strings.NewReader(form.Encode())).
		Do()
	if result.Error() != nil {
		logger.Errorf("GET %s", stripToken(endpoint))
		logger.Errorf("token validation request failed: %s", result.Error())
		return false
	}

	logger.Printf("%d GET %s %s", result.StatusCode(), stripToken(endpoint), result.Body())

	if result.StatusCode() == 200 {
		json, err := result.UnmarshalJSON()
		if err != nil {
			return false
		}
		if v, _ := json.Get("active").Bool(); v {
			return true
		}
		return false
	}
	logger.Errorf("token validation request failed: status %d - %s", result.StatusCode(), result.Body())
	return false
}
