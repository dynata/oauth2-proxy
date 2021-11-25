package constants

type ContextTokenAuthPath struct{}
type ContextSkipRefreshInterval struct{}
type ContextOriginalRefreshToken struct{}
type ContextIsMockOauthTokenRequestCall struct{}
type ContextSkipIDTokenValidation struct{}

const (
	RedirectLibHeader       = "X-Redirect-URI-Lib"
	AuthMessageType         = "AUTHENTITCATION"
	SilentAuthMessageType   = "SILENT_AUTHENTICATION"
	LogoutMessageType       = "LOGOUT"
	CheckSessionMessageType = "CHECK_SESSION"
)
