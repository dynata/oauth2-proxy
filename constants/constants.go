package constants

type AuthServerContextConstant int

const (
	ContextClientId             AuthServerContextConstant = iota
	ContextTokenAuthPath        AuthServerContextConstant = iota
	ContextSkipRefreshInterval  AuthServerContextConstant = iota
	ContextOriginalRefreshToken AuthServerContextConstant = iota
)
