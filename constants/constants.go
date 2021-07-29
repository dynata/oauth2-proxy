package constants

type AuthServerContextConstant int

const (
	ContextClientId AuthServerContextConstant = iota
	ContextTokenAuthPath
	ContextSkipRefreshInterval
	ContextOriginalRefreshToken
	ContextIsMockOauthTokenRequestCall
)
