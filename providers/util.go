package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/bitly/go-simplejson"
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
			case "acr_values":
				acrValues = v
			case "prompt":
				prompt = v
			case "approval_prompt":
				approvalPrompt = v
			case "scope":
				scope = v
			case "kc_idp_hint":
				extraParams.Add(k, v)
			}
		}
	}

	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	if acrValues != "" {
		params.Add("acr_values", acrValues)
	}
	if prompt != "" {
		params.Set("prompt", prompt)
	} else { // Legacy variant of the prompt param:
		params.Set("approval_prompt", approvalPrompt)
	}
	params.Add("scope", scope)
	params.Set("client_id", clientId)
	params.Set("response_type", "code")
	params.Add("state", state)
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
