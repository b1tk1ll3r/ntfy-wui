package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/ntfywui/internal/security"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Roles lists all roles in ascending order of privileges.
var Roles = []Role{RoleViewer, RoleOperator, RoleAdmin}

func (r Role) Valid() bool { return r == RoleViewer || r == RoleOperator || r == RoleAdmin }

func (r Role) level() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

// AtLeast reports whether r grants at least the privileges of need.
func (r Role) AtLeast(need Role) bool { return r.level() >= need.level() && r.level() > 0 }

type Admin struct {
	Username    string `json:"username"`
	Role        Role   `json:"role"`
	PassHash    string `json:"pass_hash"`
	TOTPSecret  string `json:"totp_secret,omitempty"`  // base32, active 2FA secret
	TOTPPending string `json:"totp_pending,omitempty"` // base32, secret awaiting confirmation
	TOTPLast    int64  `json:"totp_last,omitempty"`    // last used TOTP time step (replay protection)
	Disabled    bool   `json:"disabled"`
	CreatedAt   int64  `json:"created_at"`
	LastLogin   int64  `json:"last_login,omitempty"`
}

func (a Admin) HasTOTP() bool { return a.TOTPSecret != "" }

// Stamp changes whenever credentials change; sessions carry it so that a
// password change or 2FA reset invalidates all other sessions.
func (a Admin) Stamp() string {
	h := sha256.Sum256([]byte(a.PassHash + "|" + a.TOTPSecret))
	return hex.EncodeToString(h[:8])
}

var (
	ErrExists       = errors.New("Admin existiert bereits")
	ErrNotFound     = errors.New("Admin nicht gefunden")
	ErrInvalidLogin = errors.New("Benutzername oder Passwort falsch")
	ErrTOTPRequired = errors.New("2FA-Code erforderlich")
	ErrInvalidTOTP  = errors.New("2FA-Code ungültig")
	ErrLastAdmin    = errors.New("Der letzte aktive Admin kann nicht entfernt, deaktiviert oder herabgestuft werden")
)

type AdminStore struct {
	mu    sync.Mutex
	path  string
	admin map[string]Admin
}

// dummyHash is verified for unknown users so that response times do not
// reveal whether a username exists.
var dummyHash = sync.OnceValue(func() string {
	return security.HashPasswordPBKDF2("dummy", []byte("ntfywui-dummy-salt"), security.PBKDF2Iterations)
})

func NewAdminStore(path string) (*AdminStore, error) {
	s := &AdminStore{path: path, admin: map[string]Admin{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.admin); err != nil {
		return nil, err
	}
	if s.admin == nil {
		s.admin = map[string]Admin{}
	}
	return s, nil
}

func (s *AdminStore) saveLocked() error {
	b, err := json.MarshalIndent(s.admin, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// EnsureBootstrap creates an initial admin if (and only if) no admins exist yet.
func (s *AdminStore) EnsureBootstrap(username, password string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.admin) > 0 {
		return false, nil
	}
	s.admin[username] = Admin{
		Username:  username,
		Role:      RoleAdmin,
		PassHash:  security.HashPassword(password),
		CreatedAt: time.Now().Unix(),
	}
	return true, s.saveLocked()
}

// List returns all admins sorted by username.
func (s *AdminStore) List() []Admin {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Admin, 0, len(s.admin))
	for _, a := range s.admin {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Username) < strings.ToLower(out[j].Username) })
	return out
}

func (s *AdminStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.admin)
}

func (s *AdminStore) Get(username string) (Admin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admin[username]
	return a, ok
}

func (s *AdminStore) Create(a Admin) error {
	if a.Username == "" {
		return errors.New("Benutzername erforderlich")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.admin[a.Username]; ok {
		return ErrExists
	}
	if a.CreatedAt == 0 {
		a.CreatedAt = time.Now().Unix()
	}
	s.admin[a.Username] = a
	return s.saveLocked()
}

// Update modifies an admin atomically. It refuses changes that would leave
// no active admin with role "admin".
func (s *AdminStore) Update(username string, fn func(a *Admin) error) (Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admin[username]
	if !ok {
		return Admin{}, ErrNotFound
	}
	before := a
	activeBefore := s.activeAdminsLocked()
	if err := fn(&a); err != nil {
		return Admin{}, err
	}
	a.Username = before.Username
	s.admin[username] = a
	if activeBefore > 0 && s.activeAdminsLocked() == 0 {
		s.admin[username] = before
		return Admin{}, ErrLastAdmin
	}
	if err := s.saveLocked(); err != nil {
		s.admin[username] = before
		return Admin{}, err
	}
	return a, nil
}

func (s *AdminStore) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admin[username]
	if !ok {
		return ErrNotFound
	}
	delete(s.admin, username)
	if s.activeAdminsLocked() == 0 {
		s.admin[username] = a
		return ErrLastAdmin
	}
	return s.saveLocked()
}

func (s *AdminStore) activeAdminsLocked() int {
	n := 0
	for _, a := range s.admin {
		if a.Role == RoleAdmin && !a.Disabled {
			n++
		}
	}
	return n
}

// CheckPassword verifies the password of an active admin. For unknown users a
// dummy hash is verified to keep timing uniform. Old hashes are upgraded.
func (s *AdminStore) CheckPassword(username, password string) (Admin, error) {
	s.mu.Lock()
	a, ok := s.admin[username]
	s.mu.Unlock()
	if !ok {
		_, _ = security.VerifyPasswordPBKDF2(password, dummyHash())
		return Admin{}, ErrInvalidLogin
	}
	okpw, _ := security.VerifyPasswordPBKDF2(password, a.PassHash)
	if !okpw || a.Disabled {
		return Admin{}, ErrInvalidLogin
	}
	if security.HashIterations(a.PassHash) < security.PBKDF2Iterations {
		newHash := security.HashPassword(password)
		if upd, err := s.Update(username, func(x *Admin) error { x.PassHash = newHash; return nil }); err == nil {
			a = upd
		}
	}
	return a, nil
}

// CheckTOTP verifies a 2FA code against the active (or, if pending is true,
// the pending) secret and records the used time step.
func (s *AdminStore) CheckTOTP(username, code string, pending bool) (Admin, error) {
	var out Admin
	var verr error
	_, err := s.Update(username, func(a *Admin) error {
		secret := a.TOTPSecret
		if pending {
			secret = a.TOTPPending
		}
		if secret == "" {
			verr = ErrInvalidTOTP
			return verr
		}
		step, ok := security.VerifyTOTPCounter(secret, code, time.Now(), a.TOTPLast)
		if !ok {
			verr = ErrInvalidTOTP
			return verr
		}
		a.TOTPLast = step
		if pending {
			a.TOTPSecret = a.TOTPPending
			a.TOTPPending = ""
		}
		out = *a
		return nil
	})
	if verr != nil {
		return Admin{}, verr
	}
	return out, err
}

// TouchLogin records the time of a successful login.
func (s *AdminStore) TouchLogin(username string) {
	_, _ = s.Update(username, func(a *Admin) error { a.LastLogin = time.Now().Unix(); return nil })
}
