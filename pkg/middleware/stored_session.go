package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/constants"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

// StoredSessionLoaderOptions cotnains all of the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage basckend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration

	ProviderData *providers.ProviderData

	// Provider based sesssion refreshing
	RefreshSessionIfNeeded func(context.Context, *sessionsapi.SessionState) (bool, error)

	// Provider based session validation.
	// If the sesssion is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSessionState func(context.Context, *sessionsapi.SessionState) bool
}

func GenerateSessionLoader(opts *StoredSessionLoaderOptions) *StoredSessionLoader {
	ss := &StoredSessionLoader{
		store:                              opts.SessionStore,
		refreshPeriod:                      opts.RefreshPeriod,
		providerData:                       opts.ProviderData,
		refreshSessionWithProviderIfNeeded: opts.RefreshSessionIfNeeded,
		validateSessionState:               opts.ValidateSessionState,
	}
	return ss
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &StoredSessionLoader{
		store:                              opts.SessionStore,
		refreshPeriod:                      opts.RefreshPeriod,
		providerData:                       opts.ProviderData,
		refreshSessionWithProviderIfNeeded: opts.RefreshSessionIfNeeded,
		validateSessionState:               opts.ValidateSessionState,
	}
	return ss.loadSession
}

func NewStoredSessionLoaderFromInstance(ss *StoredSessionLoader) alice.Constructor {
	return ss.loadSession
}

// StoredSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type StoredSessionLoader struct {
	store                              sessionsapi.SessionStore
	refreshPeriod                      time.Duration
	providerData                       *providers.ProviderData
	refreshSessionWithProviderIfNeeded func(context.Context, *sessionsapi.SessionState) (bool, error)
	validateSessionState               func(context.Context, *sessionsapi.SessionState) bool
}

func (s *StoredSessionLoader) GetStoredSessionLoader(opts *StoredSessionLoaderOptions) *StoredSessionLoader {
	ss := &StoredSessionLoader{
		store:                              opts.SessionStore,
		refreshPeriod:                      opts.RefreshPeriod,
		providerData:                       opts.ProviderData,
		refreshSessionWithProviderIfNeeded: opts.RefreshSessionIfNeeded,
		validateSessionState:               opts.ValidateSessionState,
	}
	return ss
}

// loadSession attempts to load a session as identified by the request cookies.
// If no session is found, the request will be passed to the next handler.
// If a session was loader by a previous handler, it will not be replaced.
func (s *StoredSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := s.getValidatedSession(rw, req)
		if err != nil {
			// In the case when there was an error loading the session,
			// we should clear the session
			logger.Errorf("Error loading cookied session: %v, removing session", err)
			err = s.store.Clear(rw, req)
			if err != nil {
				logger.Errorf("Error removing session: %v", err)
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getValidatedSession is responsible for loading a session and making sure
// that is is valid.
func (s *StoredSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session, err := s.store.Load(req)
	if err != nil {
		return nil, err
	}
	if session == nil {
		// No session was found in the storage, nothing more to do
		return nil, nil
	}

	originalRefreshToken := session.RefreshToken
	ctx := context.WithValue(req.Context(), constants.ContextOriginalRefreshToken{}, originalRefreshToken)
	req = req.Clone(ctx)

	if s.providerData != nil && session.ClientId != "" {
		clientId := session.ClientId
		middlewareapi.GetRequestScope(req).RequestedClientVerifier = s.providerData.ClientsVerifiers[clientId]
	}

	err = s.refreshSessionIfNeeded(rw, req, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, nil
}

// Used when we required each http request to refresh token
func (s *StoredSessionLoader) RefreshSessionForcefully(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	logger.Printf("Refreshing access token using refresh token")

	_, err := s.refreshSessionWithProvider(rw, req, session)
	if err != nil {
		return err
	}

	/* if !refreshed {
		// Session wasn't refreshed, so make sure it's still valid
		return s.validateSession(req.Context(), session)
	} */
	return nil
}

// refreshSessionIfNeeded will attempt to refresh a session if the session
// is older than the refresh period.
// It is assumed that if the provider refreshes the session, the session is now
// valid.
// If the session requires refreshing but the provider does not refresh it,
// we must validate the session to ensure that the returned session is still
// valid.
func (s *StoredSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	if err := s.validateSession(req.Context(), session); err != nil {
		logger.Printf("Session validation failed!")
		return err
	}

	if s.refreshPeriod <= time.Duration(0) || session.Age() < s.refreshPeriod {
		// Refresh is disabled or the session is not old enough, do nothing
		return nil
	}

	logger.Printf("Refreshing %s old session cookie for %s (refresh after %s)", session.Age(), session, s.refreshPeriod)
	_, err := s.refreshSessionWithProvider(rw, req, session)
	if err != nil {
		return err
	}

	// if !refreshed {
	// 	// Session wasn't refreshed, so make sure it's still valid
	// 	return s.validateSession(req.Context(), session)
	// }
	return nil
}

// refreshSessionWithProvider attempts to refresh the sessinon with the provider
// and will save the session if it was updated.
func (s *StoredSessionLoader) refreshSessionWithProvider(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) (bool, error) {
	refreshed, err := s.refreshSessionWithProviderIfNeeded(req.Context(), session)
	if err != nil {
		return false, fmt.Errorf("error refreshing access token: %v", err)
	}

	if !refreshed {
		return false, nil
	}

	// Because the session was refreshed, make sure to save it
	_, err = s.store.Save(rw, req, session)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthError, "error saving session: %v", err)
		return false, fmt.Errorf("error saving session: %v", err)
	}
	return true, nil
}

// validateSession checks whether the session has expired and performs
// provider validation on the session.
// An error implies the session is not longer valid.
func (s *StoredSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.validateSessionState(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
