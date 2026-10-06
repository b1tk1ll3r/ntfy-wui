package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

type SessionManager struct {
	cookieName string
	path       string
	secure     bool
	maxAge     time.Duration
	aead       cipher.AEAD
}

func NewSessionManager(secret []byte, cookieName, path string, secure bool, maxAge time.Duration) (*SessionManager, error) {
	// Derive a dedicated 32-byte key for AES-256-GCM.
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("ntfywui session v1"))
	block, err := aes.NewCipher(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = "/"
	}
	if maxAge <= 0 {
		maxAge = 12 * time.Hour
	}
	return &SessionManager{cookieName: cookieName, path: path, secure: secure, maxAge: maxAge, aead: aead}, nil
}

// Flash is a one-time message shown on the next rendered page.
type Flash struct {
	Kind   string `json:"k"`           // success, error, info
	Msg    string `json:"m"`           // message
	Secret string `json:"s,omitempty"` // optional value to copy (token, ...), shown once
}

// Session contents are encrypted and authenticated (AES-GCM) inside the cookie.
type Session struct {
	User  string `json:"user,omitempty"`
	Stamp string `json:"stamp,omitempty"` // must match the admin's current auth stamp
	CSRF  string `json:"csrf"`
	Flash *Flash `json:"flash,omitempty"`
	// Pending holds a user whose password was verified but who still has to
	// enter a 2FA code (until PendingExp).
	Pending    string `json:"pending,omitempty"`
	PendingExp int64  `json:"pending_exp,omitempty"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
}

// Get returns the session from the request. It always returns a non-nil session;
// ok is false if there was no valid session cookie.
func (sm *SessionManager) Get(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(sm.cookieName)
	if err != nil || c.Value == "" {
		return &Session{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) < sm.aead.NonceSize() {
		return &Session{}, false
	}
	pt, err := sm.aead.Open(nil, raw[:sm.aead.NonceSize()], raw[sm.aead.NonceSize():], []byte(sm.cookieName))
	if err != nil {
		return &Session{}, false
	}
	var s Session
	if err := json.Unmarshal(pt, &s); err != nil {
		return &Session{}, false
	}
	if s.ExpiresAt != 0 && time.Now().Unix() > s.ExpiresAt {
		return &Session{}, false
	}
	return &s, true
}

// Save writes the session cookie. Expiry is absolute (set once at creation).
func (sm *SessionManager) Save(w http.ResponseWriter, s *Session) error {
	now := time.Now()
	if s.IssuedAt == 0 {
		s.IssuedAt = now.Unix()
	}
	if s.ExpiresAt == 0 {
		s.ExpiresAt = now.Add(sm.maxAge).Unix()
	}
	pt, err := json.Marshal(s)
	if err != nil {
		return err
	}
	nonce := make([]byte, sm.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	raw := sm.aead.Seal(nonce, nonce, pt, []byte(sm.cookieName))
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     sm.path,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Until(time.Unix(s.ExpiresAt, 0)).Seconds()),
	})
	return nil
}

func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     sm.path,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
