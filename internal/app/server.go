package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/ntfywui/internal/ntfy"
	"github.com/yourorg/ntfywui/internal/security"
	"github.com/yourorg/ntfywui/internal/store"
)

type Config struct {
	BasePath       string
	DataDir        string
	Secret         []byte
	CookieSecure   bool
	TrustedProxies []*net.IPNet
	NtfyBin        string
	NtfyConfig     string
	NtfyTimeout    time.Duration
	NtfyURL        string // optional: base URL of the ntfy server (publishing, health check)
	Version        string
	Logger         *log.Logger
}

type Server struct {
	cfg        Config
	mux        *http.ServeMux
	renderer   *Renderer
	sessions   *security.SessionManager
	admins     *store.AdminStore
	audit      *store.AuditLog
	rl         *security.RateLimiter
	loginFails *security.FailureLimiter
	ipCfg      security.RealIPConfig
	ntfy       *ntfy.Client
	httpc      *http.Client
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	cfg.BasePath = strings.TrimRight(cfg.BasePath, "/")
	cfg.NtfyURL = strings.TrimRight(cfg.NtfyURL, "/")

	cookiePath := cfg.BasePath + "/"
	sess, err := security.NewSessionManager(cfg.Secret, "ntfywui_session", cookiePath, cfg.CookieSecure, 12*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("sessions: %w", err)
	}
	admins, err := store.NewAdminStore(filepath.Join(cfg.DataDir, "admins.json"))
	if err != nil {
		return nil, fmt.Errorf("admin store: %w", err)
	}
	audit, err := store.NewAuditLog(filepath.Join(cfg.DataDir, "audit.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	renderer, err := NewRenderer(cfg.BasePath)
	if err != nil {
		return nil, fmt.Errorf("templates: %w", err)
	}

	s := &Server{
		cfg:        cfg,
		mux:        http.NewServeMux(),
		renderer:   renderer,
		sessions:   sess,
		admins:     admins,
		audit:      audit,
		rl:         security.NewRateLimiter(60, 10, 10*time.Minute),
		loginFails: security.NewFailureLimiter(5, 15*time.Minute, 15*time.Minute),
		ipCfg:      security.RealIPConfig{TrustedProxies: cfg.TrustedProxies},
		ntfy: &ntfy.Client{
			Bin:     cfg.NtfyBin,
			Config:  cfg.NtfyConfig,
			Timeout: cfg.NtfyTimeout,
		},
		httpc: &http.Client{Timeout: 10 * time.Second},
	}
	s.routes()
	return s, nil
}

func (s *Server) BasePath() string { return s.cfg.BasePath }

func (s *Server) Close() error { return s.audit.Close() }

func (s *Server) BootstrapAdmin(user, pass string) (bool, error) {
	return s.admins.EnsureBootstrap(user, pass)
}

func (s *Server) publishEnabled() bool { return s.cfg.NtfyURL != "" }

func (s *Server) Handler() http.Handler {
	h := http.Handler(s.mux)
	h = s.csrfProtect(h)
	if s.cfg.BasePath != "" {
		h = http.StripPrefix(s.cfg.BasePath, h)
	}
	h = s.rl.Middleware(func(r *http.Request) string { return security.RealIP(r, s.ipCfg) })(h)
	h = security.SecureHeaders(h)
	return h
}

func (s *Server) routes() {
	m := s.mux
	viewer := func(h http.HandlerFunc) http.Handler { return s.auth(store.RoleViewer, h) }
	operator := func(h http.HandlerFunc) http.Handler { return s.auth(store.RoleOperator, h) }
	admin := func(h http.HandlerFunc) http.Handler { return s.auth(store.RoleAdmin, h) }

	// Public
	m.HandleFunc("GET /{$}", s.handleIndex)
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))
	m.HandleFunc("GET /login", s.handleLoginForm)
	m.HandleFunc("POST /login", s.handleLogin)
	m.HandleFunc("GET /login/2fa", s.handleLogin2FAForm)
	m.HandleFunc("POST /login/2fa", s.handleLogin2FA)
	m.HandleFunc("POST /logout", s.handleLogout)

	// Viewer
	m.Handle("GET /dashboard", viewer(s.handleDashboard))
	m.Handle("GET /users", viewer(s.handleUsers))
	m.Handle("GET /users/{name}", viewer(s.handleUser))
	m.Handle("GET /account", viewer(s.handleAccount))
	m.Handle("POST /account", viewer(s.handleAccountPost))

	// Operator
	m.Handle("POST /users", operator(s.handleUserCreate))
	m.Handle("POST /users/{name}/{action}", operator(s.handleUserAction))
	m.Handle("GET /access", operator(s.handleAccess))
	m.Handle("POST /access", operator(s.handleAccessPost))
	m.Handle("GET /tokens", operator(s.handleTokens))
	m.Handle("POST /tokens", operator(s.handleTokensPost))
	m.Handle("GET /publish", operator(s.handlePublish))
	m.Handle("POST /publish", operator(s.handlePublishPost))

	// Admin
	m.Handle("GET /admins", admin(s.handleAdmins))
	m.Handle("POST /admins", admin(s.handleAdminsPost))
	m.Handle("GET /audit", admin(s.handleAudit))
	m.Handle("GET /audit/export", admin(s.handleAuditExport))

	// Everything else
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.renderError(w, r, http.StatusNotFound, "Seite nicht gefunden", "Die angeforderte Seite existiert nicht.")
	})
}

// --- Request context ---

type ctxKey int

const adminKey ctxKey = 1

func adminFrom(r *http.Request) store.Admin {
	a, _ := r.Context().Value(adminKey).(store.Admin)
	return a
}

// currentAdmin returns the logged in admin if the session is valid.
func (s *Server) currentAdmin(r *http.Request) (store.Admin, bool) {
	if a, ok := r.Context().Value(adminKey).(store.Admin); ok {
		return a, true
	}
	sess, ok := s.sessions.Get(r)
	if !ok || sess.User == "" {
		return store.Admin{}, false
	}
	a, ok := s.admins.Get(sess.User)
	if !ok || a.Disabled || sess.Stamp != a.Stamp() {
		return store.Admin{}, false
	}
	return a, true
}

func (s *Server) auth(minRole store.Role, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.currentAdmin(r)
		if !ok {
			back := r.URL.Path
			if r.Method != http.MethodGet {
				back = ""
			}
			target := "/login"
			if back != "" && back != "/dashboard" {
				target += "?next=" + urlQueryEscape(back)
			}
			http.Redirect(w, r, s.abs(target), http.StatusSeeOther)
			return
		}
		if !a.Role.AtLeast(minRole) {
			s.renderError(w, r, http.StatusForbidden, "Keine Berechtigung",
				"Für diese Aktion ist mindestens die Rolle „"+roleLabel(minRole)+"“ erforderlich.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminKey, a)))
	})
}

// csrfProtect validates the CSRF token of all state-changing requests.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		sess, _ := s.sessions.Get(r)
		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			got = r.PostFormValue("csrf")
		}
		if !security.TokensEqual(got, sess.CSRF) {
			s.renderError(w, r, http.StatusForbidden, "Sicherheitsprüfung fehlgeschlagen",
				"Das Formular ist abgelaufen oder ungültig (CSRF). Bitte lade die Seite neu und versuche es erneut. "+
					"Falls das Problem bleibt: Läuft die WebUI ohne HTTPS, muss NTFYWUI_COOKIE_SECURE=false gesetzt sein.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string { return security.RealIP(r, s.ipCfg) }

func (s *Server) auditEvent(r *http.Request, action, target string, meta map[string]string) {
	actor := adminFrom(r).Username
	if actor == "" {
		if a, ok := s.currentAdmin(r); ok {
			actor = a.Username
		}
	}
	s.audit.Append(store.AuditEvent{
		Actor:  actor,
		IP:     s.clientIP(r),
		UA:     r.UserAgent(),
		Action: action,
		Target: target,
		Meta:   meta,
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentAdmin(r); ok {
		http.Redirect(w, r, s.abs("/dashboard"), http.StatusFound)
		return
	}
	http.Redirect(w, r, s.abs("/login"), http.StatusFound)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}
