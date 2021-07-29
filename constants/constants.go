package constants

type AuthServerContextConstant int

const (
	ContextClientId             AuthServerContextConstant = iota
	ContextTokenAuthPath        AuthServerContextConstant = iota
	ContextSkipRefreshToken     AuthServerContextConstant = iota
	ContextOriginalRefreshToken AuthServerContextConstant = iota
)
