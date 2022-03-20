package token

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	jwtgo "github.com/golang-jwt/jwt/v4"
	pe_jwt "github.com/researchnow/pe-go-lib/jwt"
	log "github.com/sirupsen/logrus"
)

// TokenBuilder ..
type TokenBuilder struct {
	jwkKeyFinder *pe_jwt.SimpleJWKFinder
	hmacSecret   []byte
	signKey      *rsa.PrivateKey
}

// NewTokenBuilder ...
func NewTokenBuilder(jwkFinder *pe_jwt.SimpleJWKFinder, hmacSecret []byte, signKey *rsa.PrivateKey) *TokenBuilder {

	return &TokenBuilder{
		jwkKeyFinder: jwkFinder,  // use to find public key to verify access token
		hmacSecret:   hmacSecret, // hmac key for signing refresh token HS256
		signKey:      signKey,    // private RSA key for signing access token
	}
}

type ClaimsTransformer func(map[string]interface{}) (map[string]interface{}, error)

// ReSigningTokenWithClaims ...
// 1. parse and verify input tokens,
// 2. inject additional key/value claims
// 3. create and reSign with new claims and proper methods (RSA and HMAC)
func (t *TokenBuilder) ReSigningTokenWithClaims(at, rt string, // claims map[string]interface{},
	claimTransformer ClaimsTransformer,
) (string, string, error) {
	l := log.WithField("function", "ReSigningTokenWithClaims")

	atNew, err := t.reSignAccessToken(at, claimTransformer)
	if err != nil {
		l.Error(err)
		return "", "", err
	}
	rtNew, err := t.reSignRefreshToken(rt, claimTransformer)
	if err != nil {
		l.Error(err)
		return "", "", err
	}

	return atNew, rtNew, nil
}

func (t *TokenBuilder) reSignAccessToken(at string, ct ClaimsTransformer) (string, error) {
	l := log.WithField("function", "reSignAccessToken")

	jwkKeyFinder, err := pe_jwt.NewSimpleJWKFinder("http://localhost:8080/auth/realms/pe/protocol/openid-connect/certs")
	tkn, err := pe_jwt.NewToken(at, jwkKeyFinder)
	if err != nil {
		return "", err
	}

	l.Debugf("is new access token verified: %v\n", tkn.Token.Valid)

	claims, err := tkn.Claims("")
	if err != nil {
		return "", fmt.Errorf("can't resolve claims in keycloak access token")
	}

	clms, err := ct(claims)
	if err != nil {
		return "", err
	}
	injectClaims(claims, clms)

	atNew := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	atNew.Header = tkn.Token.Header // preserve the kid
	// l.Debugf("header %v: ", atNew.Header)
	// l.Debugf("claims %v: ", atNew.Claims)
	signBytes, err := ioutil.ReadFile("./kc.local.private.pem")
	if err != nil {
		l.Error(err)
		//return nil
	}

	signKey, err := jwtgo.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		l.Error(err)
		//return nil
	}
	signedToken, err := atNew.SignedString(signKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (t *TokenBuilder) reSignRefreshToken(refreshToken string, ct ClaimsTransformer) (string, error) {
	l := log.WithField("function", "reSignRefreshToken")

	rt, err := jwtgo.Parse(refreshToken, func(token *jwtgo.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		hmacSecretHex := []byte("0a079b870b4f04557ac04290e3ef5714cefa9b12b4a81f5d3792684ff288384d3ae2de33a77cfbb453e452d6e6aaa63c52b3967d19f7ff0c8ea10a892d596360")
		hmacSecret := make([]byte, hex.DecodedLen(len(hmacSecretHex)))
		return hmacSecret, nil
	})
	if err != nil {
		return "", err
	}

	l.Debugf("is refresh token verified: %v: ", rt.Valid)

	rtClaims, ok := rt.Claims.(jwtgo.MapClaims)
	if !ok {
		return "", fmt.Errorf("can't resolve claims in keycloak refresh token")
	}

	clms, err := ct(rtClaims)
	if err != nil {
		return "", err
	}
	injectClaims(rtClaims, clms)

	rtNew := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, rtClaims)
	rtNew.Header = rt.Header // preserve the kid
	// l.Debugf("header %v: ", rtNew.Header)
	// l.Debugf("claims %v: ", rtNew.Claims)

	signedRToken, err := rtNew.SignedString(t.hmacSecret)
	if err != nil {
		return "", err
	}

	return signedRToken, nil
}

func injectClaims(claims jwtgo.MapClaims, clms map[string]interface{}) jwtgo.MapClaims {
	if clms == nil {
		return claims
	}
	for k, v := range clms {
		claims[k] = v
	}

	return claims
}
