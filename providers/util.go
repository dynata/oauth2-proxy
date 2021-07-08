package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/bitly/go-simplejson"
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

func makeLoginURL(p *ProviderData, redirectURI, state string, extraParams url.Values) url.URL {
	a := *p.LoginURL

	clientId := p.ClientID
	acrValues := p.AcrValues
	prompt := p.Prompt
	approvalPrompt := p.ApprovalPrompt
	scope := p.Scope

	dynamicClient := p.DynamicClientConfig["dynamic_client"]
	if len(dynamicClient) > 3 {
		clientId = dynamicClient[0]
		if dynamicClient[2] != "" { //kc_idp_hint
			extraParams.Add("kc_idp_hint", dynamicClient[2])
		}
		scope = dynamicClient[4]
		// redirectURI = dynamicClient[5] //All client must redirect to same URL defined in config
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
