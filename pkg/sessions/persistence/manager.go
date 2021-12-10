package persistence

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/oauth2-proxy/oauth2-proxy/v7/constants"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// Manager wraps a Store and handles the implementation details of the
// sessions.SessionStore with its use of session tickets
type Manager struct {
	Store   Store
	Options *options.Cookie
}

// NewManager creates a Manager that can wrap a Store and manage the
// sessions.SessionStore implementation details
func NewManager(store Store, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		Store:   store,
		Options: cookieOpts,
	}
}

// Save saves a session in a persistent Store. Save will generate (or reuse an
// existing) ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) (string, error) {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		now := time.Now()
		s.CreatedAt = &now
	}
	tckt, err := m.decodeMockOauthTokenRequest(req, m.Options)
	if err != nil || tckt == nil {
		tckt, err = decodeTicketFromRequest(req, m.Options)
	}
	if err != nil {
		tckt, err = newTicket(m.Options)
		if err != nil {
			return "", fmt.Errorf("error creating a session ticket: %v", err)
		}
	}

	ticket_uuid := uuid.NewString() + "." + uuid.NewString() + "." + uuid.NewString()

	err = tckt.saveSession(req.Context(), s, ticket_uuid, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Save(req.Context(), key, val, exp)
	})
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString([]byte(ticket_uuid)), tckt.setCookie(rw, req, s)
}

// Load reads sessions.SessionState information from a session store. It will
// use the session ticket from the http.Request's cookie.
func (m *Manager) Load(req *http.Request) (*sessions.SessionState, error) {
	tckt, err := m.decodeMockOauthTokenRequest(req, m.Options)
	if err != nil || tckt == nil {
		// cookie will not be preset in barbican API request. So nil ticket will be returned
		tckt, err = decodeTicketFromRequest(req, m.Options)
		if err != nil {
			return nil, err
		}
	}

	return tckt.loadSession(
		func(key string) ([]byte, error) {
			return m.Store.Load(req.Context(), key)
		},
		m.Store.Lock,
	)
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the Store.
func (m *Manager) Clear(rw http.ResponseWriter, req *http.Request) error {
	scope := middleware.GetRequestScope(req)
	clientId := req.FormValue("client_id")
	if clientId == "" {
		// clientId = req.Context().Value(constants.ContextAppliedClientId{}).(string)
		for _, clientId := range scope.AllClientIDs {
			err := m.clearCookieAndSession(rw, req, clientId)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		return m.clearCookieAndSession(rw, req, clientId)
	}
}

func (m *Manager) clearCookieAndSession(rw http.ResponseWriter, req *http.Request, clientId string) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		tckt = &ticket{
			options: m.Options,
		}
		tckt.clearCookie(rw, req, clientId)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	tckt.clearCookie(rw, req, clientId)
	return tckt.clearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	})
}

func (m *Manager) decodeMockOauthTokenRequest(req *http.Request, cookieOpts *options.Cookie) (*ticket, error) {
	// first mock API processing is done with provided code to get session from
	mockTokenPath := fmt.Sprintf("%v", req.Context().Value(constants.ContextTokenAuthPath{}))
	encodedUserCode := req.FormValue("code")
	userRefreshToken := req.FormValue("refresh_token")

	if encodedUserCode != "" {
		if mockTokenPath != "" && req.URL.Path == mockTokenPath {
			decodedUserCode, err := base64.RawURLEncoding.DecodeString(encodedUserCode)
			if err == nil {
				return decodeUUIDTicket(string(decodedUserCode),
					func(key string) ([]byte, error) {
						return m.Store.Load(req.Context(), key)
					},
					func(key string) error {
						return m.Store.Clear(req.Context(), key)
					},
					cookieOpts)
			}
		}
		/* Deprecated */
	} else if userRefreshToken != "" {
		if mockTokenPath != "" && req.URL.Path == mockTokenPath {
			return loadSessionFromRefreshToken(
				userRefreshToken,
				cookieOpts,
				func(key string) ([]byte, error) {
					return m.Store.Load(req.Context(), key)
				},
				m.Store.Lock,
			)
		}
	}
	return nil, errors.New("proxy mock api urls matching failed")
}
