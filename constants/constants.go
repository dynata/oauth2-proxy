package constants

type AuthServerContextConstant int

const (
	ContextTokenAuthPath = iota
	ContextSkipRefreshInterval
	ContextOriginalRefreshToken
	ContextIsMockOauthTokenRequestCall
)
