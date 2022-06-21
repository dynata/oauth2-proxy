package token

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"

	corpus "github.com/dynata/proto-api/go/iam/corpus/v1"
	"github.com/golang-jwt/jwt"
	jwtgo "github.com/golang-jwt/jwt/v4"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	pe_jwt "github.com/researchnow/pe-go-lib/jwt"
	log "github.com/sirupsen/logrus"
)

// TokenProcessor ..
type TokenProcessor struct {
	jwkKeyFinder            *pe_jwt.SimpleJWKFinder
	hmacSecret              []byte
	signKey                 *rsa.PrivateKey
	corpusClient            corpus.CorpusClient
	claimTransformerToApply util.ClaimsTransformer
}

func (t *TokenProcessor) GetClaimTransformerToApply() util.ClaimsTransformer {
	return t.claimTransformerToApply
}
func (t *TokenProcessor) SetClaimTransformerToApply(claimTransformerToApply util.ClaimsTransformer) {
	t.claimTransformerToApply = claimTransformerToApply
}

// SetUsers configures allowed usernames
func MakeTokenProcessor(hmacSecretKeyPath string, rsaPrivateKeyPath string, corpusClient corpus.CorpusClient, jwksURL *url.URL) (*TokenProcessor, error) {
	//
	jwkKeyFinder, err := pe_jwt.NewSimpleJWKFinder(jwksURL.String())
	if err != nil {
		//log.Fatal("Invalid JWK url provided")
		return nil, err
	}

	hmacSecretFileContent, err := ioutil.ReadFile(hmacSecretKeyPath)
	if err != nil {
		return nil, err
	}
	content := string(hmacSecretFileContent)
	contentTrimmed := strings.TrimSuffix(content, "\n")
	hmacSecret, err := hex.DecodeString(contentTrimmed)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		//log.Fatal("RSA private file parsing issue")
		return nil, err
	}

	builder := NewTokenProcessor(jwkKeyFinder, hmacSecret, signKey)
	builder.corpusClient = corpusClient

	return builder, nil
}

// SetUsers configures allowed usernames
func MakeTokenProcessorFromKeys(hmacSecretKey string, rsaPrivateKey string, corpusClient corpus.CorpusClient, jwksURL *url.URL) (*TokenProcessor, error) {
	//
	jwkKeyFinder, err := pe_jwt.NewSimpleJWKFinder(jwksURL.String())
	if err != nil {
		return nil, err
	}

	hmacSecretHex := []byte(hmacSecretKey)
	hmacSecret := make([]byte, hex.DecodedLen(len(hmacSecretHex)))
	_, err = hex.Decode(hmacSecret, hmacSecretHex)
	if err != nil {
		return nil, err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKey))
	if err != nil {
		//log.Fatal("RSA private file parsing issue")
		return nil, err
	}

	builder := NewTokenProcessor(jwkKeyFinder, hmacSecret, signKey)
	builder.corpusClient = corpusClient

	return builder, nil
}

// NewTokenProcessor ...
func NewTokenProcessor(jwkFinder *pe_jwt.SimpleJWKFinder, hmacSecret []byte, signKey *rsa.PrivateKey) *TokenProcessor {

	return &TokenProcessor{
		jwkKeyFinder: jwkFinder,  // use to find public key to verify access token
		hmacSecret:   hmacSecret, // hmac key for signing refresh token HS256
		signKey:      signKey,    // private RSA key for signing access token
	}
}

func (t *TokenProcessor) GetClaimsFromAccessToken(accessToken string) (jwtgo.MapClaims, error) {
	l := log.WithField("function", "GetClaimsFromAccessToken()")

	tkn, err := pe_jwt.NewToken(accessToken, t.jwkKeyFinder)
	if err != nil {
		return nil, err
	}

	l.Debugf("is access token verified: %v\n", tkn.Token.Valid)

	claims, ok := tkn.Token.Claims.(jwtgo.MapClaims)
	if !ok {
		return nil, fmt.Errorf("can't resolve claims in keycloak access token")
	}
	return claims, nil
}

func (t *TokenProcessor) GetClaimsFromRefreshToken(refreshToken string) (jwtgo.MapClaims, error) {
	l := log.WithField("function", "GetClaimsFromRefreshToken()")

	rt, err := jwtgo.Parse(refreshToken, t.refreshTokenKeyFunc)

	if err != nil {
		return nil, err
	}

	l.Debugf("is refresh token verified: %v: ", rt.Valid)

	rtClaims, ok := rt.Claims.(jwtgo.MapClaims)
	if !ok {
		return nil, fmt.Errorf("can't resolve claims in keycloak refresh token")
	}

	return rtClaims, nil
}

func (t *TokenProcessor) GetEffectiveCompanyIDFromClaims(claims jwtgo.MapClaims, primaryCompanyID int64) int64 {
	var effCompID int64
	if _, ok := claims["effective_company_id"]; ok {
		effCompIDClaim := claims["effective_company_id"].(float64)
		effCompID = int64(effCompIDClaim)
	} else {
		effCompID = 0
	}

	if effCompID == 0 {
		effCompID = primaryCompanyID
	}

	return effCompID
}

func (t *TokenProcessor) GetEffectiveCompanyIDFromToken(accessToken string, primaryCompanyID int64) int64 {
	var effCompID int64
	claims, err := t.GetClaimsFromAccessToken(accessToken)
	if err != nil {
		effCompID = 0
	}
	if _, ok := claims["effective_company_id"]; ok {
		effCompIDClaim := claims["effective_company_id"].(float64)
		effCompID = int64(effCompIDClaim)
	} else {
		effCompID = 0
	}

	if effCompID == 0 {
		effCompID = primaryCompanyID
	}

	return effCompID
}

// GetPrimaryCompID will return the primary compnay ID from userInfo if present else return 0, error
func (t *TokenProcessor) GetPrimaryCompID(userInfo *corpus.UserDetailResponse) (int64, error) {
	if userInfo == nil {
		return 0, errors.New("userInfo is nil")
	}

	for _, c := range userInfo.Companies {
		if c.GetIsPrimary() {
			return c.GetId(), nil
		}
	}

	return 0, errors.New("user has no primary company")
}

func (t *TokenProcessor) GetSubject(claims jwtgo.MapClaims) *corpus.SubjectID {
	sub := claims["sub"].(string)
	if sub == "" {
		logger.Printf("Claim sub not found")
		return nil
	}
	req := &corpus.SubjectID{
		SubId: sub,
	}
	return req
}

func (t *TokenProcessor) ReSignTokensWithClaimsInSession(session *sessionsapi.SessionState, ct util.ClaimsTransformer) error {
	// re-sign the access and refresh tokens

	newAccessTkn, newRefreshTkn, err := t.ReSignTokenWithClaims(session.AccessToken, session.RefreshToken, ct)
	if err != nil {
		return err
	}
	// // assign the re-signed tokens respectively
	accessTokenClaims, err := t.GetClaimsFromAccessToken(newAccessTkn)
	if err != nil {
		return err
	}
	session.AccessToken = newAccessTkn
	session.AccessExpiresIn = accessTokenClaims["exp"].(float64)

	refreshTokenClaims, err := t.GetClaimsFromRefreshToken(newRefreshTkn)
	if err != nil {
		return err
	}
	session.RefreshToken = newRefreshTkn
	session.RefreshExpiresIn = refreshTokenClaims["exp"].(float64)

	return nil
}

// ReSignTokenWithClaims ...
// 1. parse and verify input tokens,
// 2. inject additional key/value claims
// 3. create and reSign with new claims and proper methods (RSA and HMAC)
func (t *TokenProcessor) ReSignTokenWithClaims(at, rt string, // claims map[string]interface{},
	claimTransformer util.ClaimsTransformer,
) (string, string, error) {
	l := log.WithField("function", "ReSigningTokenWithClaims")

	atNew, err := t.ReSignAccessToken(at, claimTransformer)
	if err != nil {
		l.Error(err)
		return "", "", err
	}

	rtNew, err := t.ReSignRefreshToken(rt, claimTransformer)
	if err != nil {
		l.Error(err)
		return "", "", err
	}

	return atNew, rtNew, nil
}

func (t *TokenProcessor) ReSignAccessToken(at string, ct util.ClaimsTransformer) (string, error) {
	l := log.WithField("function", "reSignAccessToken")

	tkn, err := pe_jwt.NewToken(at, t.jwkKeyFinder)
	if err != nil {
		return "", err
	}

	l.Debugf("is new access token verified: %v\n", tkn.Token.Valid)

	claims, ok := tkn.Token.Claims.(jwtgo.MapClaims)

	if !ok {
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

	signedToken, err := atNew.SignedString(t.signKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (t *TokenProcessor) refreshTokenKeyFunc(token *jwtgo.Token) (interface{}, error) {
	// Don't forget to validate the alg is what you expect:
	if _, ok := token.Method.(*jwtgo.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
	return t.hmacSecret, nil
}

func (t *TokenProcessor) ReSignRefreshToken(refreshToken string, ct util.ClaimsTransformer) (string, error) {
	l := log.WithField("function", "reSignRefreshToken")

	rt, err := jwtgo.Parse(refreshToken, t.refreshTokenKeyFunc)

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

// CreateClaimsTransformer creates a new ClaimsTransformer for the passed company id. Claims will be filtered
// based on data from corpus.
func (t *TokenProcessor) CreateClaimsTransformer(ctx context.Context, compID int64) (util.ClaimsTransformer, error) {
	l := log.WithField("function", "CreateClaimsTransformer()")
	clientRolesResp, err := t.corpusClient.ListProductLineClientRolesByCompanyID(
		ctx,
		&corpus.RequestID{Id: compID},
	)
	if err != nil {
		l.WithField("err", err).Error()
		return nil, err
	}

	transformer, err := util.CreateClaimsTransformer(compID, clientRolesResp.Clients)
	if err != nil {
		l.WithFields(log.Fields{"err": err}).Error("CreateClaimsTransformer()")
		return nil, err
	}
	return transformer, nil
}

func (t *TokenProcessor) GetClaimsTransformerFromToken(ctx context.Context, claims jwtgo.MapClaims, userInfo *corpus.UserDetailResponse) (util.ClaimsTransformer, error) {
	l := log.WithField("function", "GetClaimsTransformerFromToken()")

	primaryCompID, err := t.GetPrimaryCompID(userInfo)
	if err != nil {
		l.Printf("No primary company found: %v", err)
		// return nil, err //since some user might not have any company set
	}

	effCompID := t.GetEffectiveCompanyIDFromClaims(claims, primaryCompID)
	transformer, err := t.CreateClaimsTransformer(ctx, effCompID)
	if err != nil {
		l.Errorf("createClaimsTransformer() failed: %v", err)
		return nil, err
	}
	return transformer, nil
}

func (t *TokenProcessor) GetUserBySubject(ctx context.Context, claims jwtgo.MapClaims) (*corpus.UserDetailResponse, error) {
	l := log.WithField("function", "GetClaimsTransformerFromToken()")

	userInfoRequest := t.GetSubject(claims)
	if userInfoRequest == nil {
		return nil, fmt.Errorf("failed to create subject from claims")
	}
	userInfo, err := t.corpusClient.GetUserBySubject(ctx, userInfoRequest)
	if userInfo == nil || err != nil {
		l.Printf("Failed to fetch user by subject from corpus: %v", err)
		return nil, err
	}
	return userInfo, nil
}
