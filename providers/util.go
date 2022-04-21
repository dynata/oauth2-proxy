package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/bitly/go-simplejson"
	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/constants"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"golang.org/x/oauth2"
)

const (
	tokenTypeBearer = "Bearer"
	tokenTypeToken  = "token"

	acceptHeader          = "Accept"
	acceptApplicationJSON = "application/json"
)

func makeAuthorizationHeader(prefix, token string, extraHeaders map[string]string) http.Header {
	header := make(http.Header)
	for key, value := range extraHeaders {
		header.Add(key, value)
	}
	header.Set("Authorization", fmt.Sprintf("%s %s", prefix, token))
	return header
}

func makeOIDCHeader(accessToken string) http.Header {
	// extra headers required by the IDP when making authenticated requests
	extraHeaders := map[string]string{
		acceptHeader: acceptApplicationJSON,
	}
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, extraHeaders)
}

func getClientIdAndSecret(ctx context.Context, clientIdOriginal, clientSecretOriginal string) (clientId, clientSecret string) {
	requestedClientConfig := middleware.GetRequestScopeFromContext(ctx).RequestedClientConfig
	if v, ok := requestedClientConfig["client_id"]; ok && v != clientId {
		clientId = v
	} else {
		clientId = clientIdOriginal
	}
	if v, ok := requestedClientConfig["client_secret"]; ok && v != clientSecret {
		clientSecret = v
	} else {
		clientSecret = clientSecretOriginal
	}
	return
}

func getClientVerifier(ctx context.Context, verifierOriginal *oidc.IDTokenVerifier) (verifier *oidc.IDTokenVerifier) {
	requestedClientVerifier := middleware.GetRequestScopeFromContext(ctx).RequestedClientVerifier
	if requestedClientVerifier != nil {
		verifier = requestedClientVerifier
	} else {
		verifier = verifierOriginal
	}
	return
}

func makeLoginURL(ctx context.Context, p *ProviderData, redirectURI, state string, extraParams url.Values) url.URL {
	a := *p.LoginURL

	clientId := p.ClientID
	acrValues := p.AcrValues
	prompt := p.Prompt
	approvalPrompt := p.ApprovalPrompt
	scope := p.Scope

	if ctx != nil {
		requestedClientConfig := middleware.GetRequestScopeFromContext(ctx).RequestedClientConfig

		for k, v := range requestedClientConfig {
			if v == "" {
				continue
			}
			switch k {
			case "client_id":
				clientId = v
			case "redirect_uri":
				redirectURI = v
			}
		}

		queryParams := ctx.Value(constants.ContextOidcLoginRequestParams{}).(url.Values)

		if queryParams != nil {
			if queryParams.Get("isLibCall") != "" {
				isLibCall := queryParams.Get("isLibCall")
				if isLibCall == "true" {
					redirectURI = redirectURI + "/lib"
				}
			}
			if queryParams.Get("acr_values") != "" {
				acrValues = queryParams.Get("acr_values")
			}
			if queryParams.Get("prompt") != "" {
				prompt = queryParams.Get("prompt")
			}
			if queryParams.Get("approval_prompt") != "" {
				approvalPrompt = queryParams.Get("approval_prompt")
			}
			if queryParams.Get("scope") != "" {
				scope = queryParams.Get("scope")
			}
			if queryParams.Get("kc_idp_hint") != "" {
				extraParams.Set("kc_idp_hint", queryParams.Get("kc_idp_hint"))
			}
		}
	}

	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	if acrValues != "" {
		params.Set("acr_values", acrValues)
	}
	if prompt != "" {
		params.Set("prompt", prompt)
	} else { // Legacy variant of the prompt param:
		params.Set("approval_prompt", approvalPrompt)
	}
	params.Set("scope", scope)
	params.Set("client_id", clientId)
	params.Set("response_type", "code")
	params.Set("state", state)
	for n, p := range extraParams {
		for _, v := range p {
			params.Add(n, v)
		}
	}
	a.RawQuery = params.Encode()
	return a
}

// getIDToken extracts an IDToken stored in the `Extra` fields of an
// oauth2.Token
func getIDToken(token *oauth2.Token) string {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return ""
	}
	return idToken
}

// formatGroup coerces an OIDC groups claim into a string
// If it is non-string, marshal it into JSON.
func formatGroup(rawGroup interface{}) (string, error) {
	if group, ok := rawGroup.(string); ok {
		return group, nil
	}

	jsonGroup, err := json.Marshal(rawGroup)
	if err != nil {
		return "", err
	}
	return string(jsonGroup), nil
}

// coerceArray extracts a field from simplejson.Json that might be a
// singleton or a list and coerces it into a list.
func coerceArray(sj *simplejson.Json, key string) []interface{} {
	array, err := sj.Get(key).Array()
	if err == nil {
		return array
	}

	single := sj.Get(key).Interface()
	if single == nil {
		return nil
	}
	return []interface{}{single}
}
