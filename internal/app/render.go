package app

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yourorg/ntfywui/internal/ntfy"
	"github.com/yourorg/ntfywui/internal/security"
	"github.com/yourorg/ntfywui/internal/store"
)

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

// assetVersion is a content hash of the static files, used for cache busting.
var assetVersion = func() string {
	h := sha256.New()
	_ = fs.WalkDir(staticFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := staticFS.ReadFile(p)
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:10]
}()

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "web/static")
	fsrv := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("v") == assetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		fsrv.ServeHTTP(w, r)
	})
}

// Page is the data passed to every template.
type Page struct {
	Title    string
	Subtitle string
	Nav      string // active navigation entry
	Admin    store.Admin
	CSRF     string
	Flash    *security.Flash
	Version  string
	Publish  bool // publishing is configured
	Data     any
}

func (p Page) LoggedIn() bool          { return p.Admin.Username != "" }
func (p Page) CanOperate() bool        { return p.Admin.Role.AtLeast(store.RoleOperator) }
func (p Page) IsAdmin() bool           { return p.Admin.Role.AtLeast(store.RoleAdmin) }
func (p Page) ActiveNav(n string) bool { return p.Nav == n }

type Renderer struct {
	basePath string
	pages    map[string]*template.Template
}

var pageFiles = []string{
	"login", "login2fa", "error", "dashboard", "users", "user", "access",
	"tokens", "publish", "admins", "audit", "account",
}

func NewRenderer(basePath string) (*Renderer, error) {
	tfs, _ := fs.Sub(templatesFS, "web/templates")
	abs := func(p string) string {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return basePath + p
	}
	funcs := template.FuncMap{
		"abs":         abs,
		"asset":       func(name string) string { return abs("/static/" + name + "?v=" + assetVersion) },
		"userURL":     func(name string) string { return abs("/users/" + url.PathEscape(name)) },
		"userAction":  func(name, action string) string { return abs("/users/" + url.PathEscape(name) + "/" + action) },
		"displayUser": displayUser,
		"initials":    initials,
		"avatarHue":   avatarHue,
		"permLabel":   permLabel,
		"permShort":   permShort,
		"permClass":   func(p string) string { return "perm-" + p },
		"roleLabel":   func(r store.Role) string { return roleLabel(r) },
		"actionLabel": actionLabel,
		"actionKind":  actionKind,
		"fmtUnix":     fmtUnix,
		"fmtTime":     fmtTime,
		"ago":         ago,
		"perms":       func() []string { return ntfy.Perms },
		"roles":       func() []store.Role { return store.Roles },
		"icon": func(name string) template.HTML {
			return template.HTML(`<svg class="icon" aria-hidden="true"><use href="#i-` + template.HTMLEscapeString(name) + `"/></svg>`)
		},
		"dict": func(kv ...any) (map[string]any, error) {
			if len(kv)%2 != 0 {
				return nil, fmt.Errorf("dict: odd number of arguments")
			}
			m := make(map[string]any, len(kv)/2)
			for i := 0; i < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m, nil
		},
		"add":    func(a, b int) int { return a + b },
		"sub":    func(a, b int) int { return a - b },
		"limit":  limitAccess,
		"plural": func(n int, one, many string) string { return map[bool]string{true: one, false: many}[n == 1] },
	}

	base, err := template.New("base").Funcs(funcs).ParseFS(tfs, "layout.html")
	if err != nil {
		return nil, err
	}
	r := &Renderer{basePath: basePath, pages: map[string]*template.Template{}}
	for _, name := range pageFiles {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(tfs, name+".html"); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		r.pages[name] = t
	}
	return r, nil
}

// render executes a page into a buffer first so that template errors never
// produce half-written responses.
func (r *Renderer) render(w http.ResponseWriter, status int, name string, p Page) error {
	t, ok := r.pages[name]
	if !ok {
		return fmt.Errorf("unknown template %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, err := buf.WriteTo(w)
	return err
}

// --- Server helpers ---

// page renders a full page: it fills in admin, CSRF token and pending flash
// message and writes the session cookie at most once.
func (s *Server) page(w http.ResponseWriter, r *http.Request, status int, name string, p Page) {
	sess, _ := s.sessions.Get(r)
	dirty := false
	if sess.CSRF == "" {
		sess.CSRF = security.NewToken()
		dirty = true
	}
	if sess.Flash != nil {
		p.Flash, sess.Flash = sess.Flash, nil
		dirty = true
	}
	if dirty {
		_ = s.sessions.Save(w, sess)
	}
	if p.Admin.Username == "" {
		p.Admin, _ = s.currentAdmin(r)
	}
	p.CSRF = sess.CSRF
	p.Version = s.cfg.Version
	p.Publish = s.publishEnabled()
	if err := s.renderer.render(w, status, name, p); err != nil {
		s.cfg.Logger.Printf("render %s: %v", name, err)
		http.Error(w, "Interner Fehler beim Rendern der Seite", http.StatusInternalServerError)
	}
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	s.page(w, r, status, "error", Page{
		Title: title,
		Data:  map[string]any{"Status": status, "Message": msg},
	})
}

// flash stores a one-time message in the session.
func (s *Server) flash(w http.ResponseWriter, r *http.Request, f security.Flash) {
	sess, _ := s.sessions.Get(r)
	sess.Flash = &f
	_ = s.sessions.Save(w, sess)
}

// done redirects with a success message.
func (s *Server) done(w http.ResponseWriter, r *http.Request, path, msg string) {
	s.flash(w, r, security.Flash{Kind: "success", Msg: msg})
	http.Redirect(w, r, s.abs(path), http.StatusSeeOther)
}

// fail redirects with an error message.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, path string, err any) {
	s.flash(w, r, security.Flash{Kind: "error", Msg: fmt.Sprint(err)})
	http.Redirect(w, r, s.abs(path), http.StatusSeeOther)
}

func (s *Server) abs(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return s.cfg.BasePath + p
}

func urlQueryEscape(v string) string { return url.QueryEscape(v) }

func userPath(name string) string { return "/users/" + url.PathEscape(name) }

// --- Template helpers ---

func displayUser(name string) string {
	if name == ntfy.Everyone {
		return "Jeder (anonym)"
	}
	return name
}

func initials(name string) string {
	if name == ntfy.Everyone {
		return "*"
	}
	name = strings.TrimLeft(name, "_.+@")
	if name == "" {
		return "?"
	}
	r := []rune(name)
	return strings.ToUpper(string(r[0]))
}

// avatarHue maps a name to one of 6 avatar color classes.
func avatarHue(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("av-%d", int(h[0])%6)
}

func permLabel(p string) string {
	switch p {
	case ntfy.PermReadWrite:
		return "Lesen & Schreiben"
	case ntfy.PermReadOnly:
		return "Nur lesen"
	case ntfy.PermWriteOnly:
		return "Nur schreiben"
	case ntfy.PermDeny:
		return "Kein Zugriff"
	}
	return p
}

func permShort(p string) string {
	switch p {
	case ntfy.PermReadWrite:
		return "RW"
	case ntfy.PermReadOnly:
		return "RO"
	case ntfy.PermWriteOnly:
		return "WO"
	case ntfy.PermDeny:
		return "—"
	}
	return p
}

func roleLabel(r store.Role) string {
	switch r {
	case store.RoleViewer:
		return "Betrachter"
	case store.RoleOperator:
		return "Operator"
	case store.RoleAdmin:
		return "Administrator"
	}
	return string(r)
}

var actionLabels = map[string]string{
	"login_ok":                   "Anmeldung",
	"login_failed":               "Anmeldung fehlgeschlagen",
	"login_locked":               "Anmeldung gesperrt",
	"logout":                     "Abmeldung",
	"ntfy_user_add":              "Benutzer angelegt",
	"ntfy_user_del":              "Benutzer gelöscht",
	"ntfy_user_change_pass":      "Passwort geändert",
	"ntfy_user_change_role":      "Rolle geändert",
	"ntfy_user_change_tier":      "Tier geändert",
	"ntfy_access_grant":          "Zugriff gewährt",
	"ntfy_access_revoke":         "Zugriff entzogen",
	"ntfy_access_reset":          "Zugriffe zurückgesetzt",
	"ntfy_token_add":             "Token erstellt",
	"ntfy_token_remove":          "Token gelöscht",
	"ntfy_publish":               "Nachricht gesendet",
	"webui_admin_create":         "Admin angelegt",
	"webui_admin_delete":         "Admin gelöscht",
	"webui_admin_set_role":       "Admin-Rolle geändert",
	"webui_admin_set_pass":       "Admin-Passwort gesetzt",
	"webui_admin_toggle_disable": "Admin (de)aktiviert",
	"webui_admin_2fa_enable":     "2FA aktiviert",
	"webui_admin_2fa_disable":    "2FA deaktiviert",
	"account_change_pass":        "Eigenes Passwort geändert",
	"audit_export":               "Audit-Log exportiert",
}

func actionLabel(a string) string {
	if l, ok := actionLabels[a]; ok {
		return l
	}
	return a
}

// actionKind classifies audit actions for color coding.
func actionKind(a string) string {
	switch {
	case a == "login_failed" || a == "login_locked":
		return "danger"
	case strings.Contains(a, "del") || strings.Contains(a, "remove") || strings.Contains(a, "reset") ||
		strings.Contains(a, "revoke") || strings.Contains(a, "disable"):
		return "warn"
	case strings.HasPrefix(a, "login") || a == "logout":
		return "muted"
	}
	return "ok"
}

func fmtUnix(ts int64) string {
	if ts == 0 {
		return "—"
	}
	return time.Unix(ts, 0).Local().Format("02.01.2006 15:04")
}

func fmtTime(v any) string {
	var t time.Time
	switch x := v.(type) {
	case time.Time:
		t = x
	case string:
		t, _ = time.Parse(time.RFC3339Nano, x)
	case int64:
		if x == 0 {
			return "—"
		}
		t = time.Unix(x, 0)
	}
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("02.01.2006 15:04:05")
}

func ago(v any) string {
	var t time.Time
	switch x := v.(type) {
	case time.Time:
		t = x
	case string:
		t, _ = time.Parse(time.RFC3339Nano, x)
	case int64:
		if x == 0 {
			return "nie"
		}
		t = time.Unix(x, 0)
	}
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return fmt.Sprintf("vor %d Min.", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("vor %d Std.", int(d.Hours()))
	case d < 48*time.Hour:
		return "gestern"
	case d < 30*24*time.Hour:
		return fmt.Sprintf("vor %d Tagen", int(d.Hours()/24))
	}
	return t.Local().Format("02.01.2006")
}

// limitAccess returns at most n entries plus the number of omitted ones.
func limitAccess(n int, list []ntfy.AccessEntry) map[string]any {
	if len(list) <= n {
		return map[string]any{"Items": list, "More": 0}
	}
	return map[string]any{"Items": list[:n], "More": len(list) - n}
}
