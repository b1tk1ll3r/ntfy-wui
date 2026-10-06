package app

import (
	"encoding/json"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yourorg/ntfywui/internal/security"
	"github.com/yourorg/ntfywui/internal/store"
)

type testEnv struct {
	t    *testing.T
	srv  *Server
	ts   *httptest.Server
	fake *fakeNtfy
}

func newTestEnv(t *testing.T, ntfyURL string) *testEnv {
	t.Helper()
	fake := newFakeNtfy()
	fake.addUser("alice", "user", map[string]string{"alerts": "read-write", "backup_*": "write-only"})
	fake.addUser("root", "admin", nil)
	s, err := NewServer(Config{
		BasePath:    "/ui",
		DataDir:     t.TempDir(),
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		NtfyTimeout: 5 * time.Second,
		NtfyURL:     ntfyURL,
		Version:     "test",
		Logger:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.ntfy.SetRunner(fake.run)
	s.rl = security.NewRateLimiter(100000, 100000, time.Minute)
	if _, err := s.BootstrapAdmin("admin", "admin-pass-123"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })
	return &testEnv{t: t, srv: s, ts: ts, fake: fake}
}

type client struct {
	env  *testEnv
	http *http.Client
	csrf string
}

func (e *testEnv) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{env: e, http: &http.Client{Jar: jar}}
}

var reCSRF = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// get fetches a page, follows redirects and remembers the CSRF token.
func (c *client) get(path string) (int, string) {
	c.env.t.Helper()
	resp, err := c.http.Get(c.env.ts.URL + "/ui" + path)
	if err != nil {
		c.env.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if m := reCSRF.FindStringSubmatch(body); m != nil {
		c.csrf = m[1]
	}
	return resp.StatusCode, body
}

// post submits a form (with CSRF token) and returns the final page after redirects.
func (c *client) post(path string, form url.Values) (int, string) {
	c.env.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf") == "" {
		form.Set("csrf", c.csrf)
	}
	resp, err := c.http.PostForm(c.env.ts.URL+"/ui"+path, form)
	if err != nil {
		c.env.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if m := reCSRF.FindStringSubmatch(body); m != nil {
		c.csrf = m[1]
	}
	return resp.StatusCode, body
}

func (c *client) login(user, pass string) string {
	c.env.t.Helper()
	c.get("/login")
	_, body := c.post("/login", url.Values{"username": {user}, "password": {pass}, "next": {"/dashboard"}})
	return body
}

func mustContain(t *testing.T, body string, subs ...string) {
	t.Helper()
	text := html.UnescapeString(body)
	for _, s := range subs {
		if !strings.Contains(text, s) {
			t.Fatalf("response does not contain %q:\n%.3000s", s, text)
		}
	}
}

func TestLoginAndAllPages(t *testing.T) {
	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":true}`))
	}))
	defer ntfySrv.Close()
	env := newTestEnv(t, ntfySrv.URL)
	c := env.client()

	// Unauthenticated access redirects to login (keeping the target).
	_, body := c.get("/users")
	mustContain(t, body, "Anmelden", `name="next" value="/users"`)

	body = c.login("admin", "wrong")
	mustContain(t, body, "Benutzername oder Passwort falsch")

	body = c.login("admin", "admin-pass-123")
	mustContain(t, body, "Übersicht", "Benutzer", "Online", "Version 2.11.0", "Aktivität")

	pages := map[string][]string{
		"/users":       {"alice", "root", "Jeder (anonym)", "alerts", "alle Topics"},
		"/users/alice": {"Zugriffsrechte", "backup_*", "Nur schreiben", "Gefahrenzone"},
		"/users/*":     {"alle nicht angemeldeten Clients", "Kein Zugriff"},
		"/access":      {"Alle Regeln", "2 Regeln"},
		"/tokens":      {"Noch keine Tokens"},
		"/publish":     {"Vorschau", ntfySrv.URL},
		"/admins":      {"admin", "Administrator"},
		"/audit":       {"Anmeldung fehlgeschlagen", "Anmeldung"},
		"/account":     {"2FA einrichten"},
	}
	for p, want := range pages {
		code, body := c.get(p)
		if code != 200 {
			t.Fatalf("GET %s: status %d\n%.2000s", p, code, body)
		}
		mustContain(t, body, want...)
	}

	code, body := c.get("/users/nobody")
	if code != 404 {
		t.Fatalf("unknown user: %d", code)
	}
	mustContain(t, body, "Benutzer nicht gefunden")
	if code, _ := c.get("/does-not-exist"); code != 404 {
		t.Fatalf("404 page: %d", code)
	}
	if code, _ := c.get("/static/app.css"); code != 200 {
		t.Fatalf("static: %d", code)
	}
	if code, _ := c.get("/healthz"); code != 200 {
		t.Fatalf("healthz: %d", code)
	}

	// Logout
	_, body = c.post("/logout", nil)
	mustContain(t, body, "Du wurdest abgemeldet")
	if _, body := c.get("/dashboard"); !strings.Contains(body, "Anmelden") {
		t.Fatal("still logged in after logout")
	}
}

func TestUserLifecycle(t *testing.T) {
	env := newTestEnv(t, "")
	c := env.client()
	c.login("admin", "admin-pass-123")
	c.get("/users")

	_, body := c.post("/users", url.Values{"username": {"--role=admin"}, "password": {"secret-123"}, "role": {"user"}})
	mustContain(t, body, "Ungültiger Benutzername")
	_, body = c.post("/users", url.Values{"username": {"bob"}, "password": {"short"}, "role": {"user"}})
	mustContain(t, body, "mindestens 8 Zeichen")

	_, body = c.post("/users", url.Values{"username": {"bob"}, "password": {"secret-123"}, "role": {"user"}, "tier": {"pro"}})
	mustContain(t, body, "Benutzer „bob“ wurde angelegt")
	if u := env.fake.users["bob"]; u == nil || u.pass != "secret-123" || u.tier != "pro" {
		t.Fatalf("fake state: %+v", u)
	}

	_, body = c.post("/users/bob/grant", url.Values{"topic": {"home_*"}, "perm": {"read-only"}})
	mustContain(t, body, "Nur lesen für „home_*“")
	_, body = c.post("/access", url.Values{"action": {"grant"}, "username": {"*"}, "topic": {"public"}, "perm": {"read-only"}})
	mustContain(t, body, "Jeder (anonym)")
	if env.fake.users["*"].grants["public"] != "read-only" {
		t.Fatal("anonymous grant not applied")
	}

	_, body = c.post("/users/bob/token-add", url.Values{"label": {"Home Assistant"}, "expires": {"30d"}})
	mustContain(t, body, "Token für „bob“ erstellt", "tk_00000000000000000000000000001", "Home Assistant")
	_, body = c.get("/tokens")
	mustContain(t, body, "Home Assistant", "tk_0000…0001")

	_, body = c.post("/users/bob/token-remove", url.Values{"token": {"tk_00000000000000000000000000001"}})
	mustContain(t, body, "Token wurde gelöscht")

	_, body = c.post("/users/bob/revoke", url.Values{"topic": {"home_*"}})
	mustContain(t, body, "Zugriff auf „home_*“ wurde entfernt")

	_, body = c.post("/users/bob/tier", url.Values{"tier": {"gold"}})
	mustContain(t, body, "tier gold does not exist")

	_, body = c.post("/users/bob/role", url.Values{"role": {"admin"}})
	mustContain(t, body, "Rolle wurde auf „admin“ gesetzt")

	_, body = c.post("/users/bob/password", url.Values{"password": {"another-pass"}})
	mustContain(t, body, "Passwort wurde geändert")
	if env.fake.users["bob"].pass != "another-pass" {
		t.Fatal("password not changed")
	}

	_, body = c.post("/users/bob/delete", nil)
	mustContain(t, body, "Benutzer „bob“ wurde gelöscht")
	if env.fake.users["bob"] != nil {
		t.Fatal("user not deleted")
	}

	_, body = c.get("/audit")
	mustContain(t, body, "Benutzer angelegt", "Token erstellt", "Benutzer gelöscht")
}

func TestCSRFAndRoles(t *testing.T) {
	env := newTestEnv(t, "")
	c := env.client()
	c.login("admin", "admin-pass-123")

	// Missing / wrong CSRF token
	code, _ := c.post("/users", url.Values{"csrf": {"forged"}, "username": {"x"}})
	if code != http.StatusForbidden {
		t.Fatalf("forged csrf: %d", code)
	}

	// Create a viewer and an operator.
	c.get("/admins")
	c.post("/admins", url.Values{"action": {"create"}, "username": {"vic"}, "password": {"viewer-pass"}, "role": {"viewer"}})
	_, body := c.post("/admins", url.Values{"action": {"create"}, "username": {"op"}, "password": {"operator-pass"}, "role": {"operator"}})
	mustContain(t, body, "Admin „op“ wurde angelegt")

	v := env.client()
	v.login("vic", "viewer-pass")
	if code, body := v.get("/users/alice"); code != 200 || strings.Contains(body, "Gefahrenzone") {
		t.Fatalf("viewer user page: %d", code)
	}
	if code, _ := v.get("/access"); code != http.StatusForbidden {
		t.Fatalf("viewer /access: %d", code)
	}
	if code, _ := v.post("/users/alice/delete", nil); code != http.StatusForbidden {
		t.Fatalf("viewer delete: %d", code)
	}

	o := env.client()
	o.login("op", "operator-pass")
	if code, _ := o.get("/access"); code != 200 {
		t.Fatalf("operator /access: %d", code)
	}
	if code, _ := o.get("/admins"); code != http.StatusForbidden {
		t.Fatalf("operator /admins: %d", code)
	}

	// Self-protection and last-admin protection.
	_, body = c.post("/admins", url.Values{"action": {"delete"}, "username": {"admin"}})
	mustContain(t, body, "eigenes Konto")

	// Password reset by another admin invalidates the target's sessions.
	c.post("/admins", url.Values{"action": {"set-pass"}, "username": {"op"}, "password": {"new-operator-pass"}})
	if _, body := o.get("/access"); !strings.Contains(body, "Anmelden") {
		t.Fatal("operator session survived password reset")
	}
	// Disabling an account logs it out as well.
	v.get("/dashboard")
	c.post("/admins", url.Values{"action": {"toggle-disable"}, "username": {"vic"}})
	if _, body := v.get("/dashboard"); !strings.Contains(body, "Anmelden") {
		t.Fatal("disabled viewer still logged in")
	}
}

func TestTwoFactorFlow(t *testing.T) {
	env := newTestEnv(t, "")
	c := env.client()
	c.login("admin", "admin-pass-123")
	c.get("/account")
	_, body := c.post("/account", url.Values{"action": {"totp-begin"}})
	mustContain(t, body, "QR-Code scannen", "<svg")

	a, _ := env.srv.admins.Get("admin")
	if a.TOTPPending == "" || a.HasTOTP() {
		t.Fatal("pending secret not stored")
	}
	_, body = c.post("/account", url.Values{"action": {"totp-confirm"}, "code": {"000000"}})
	if security.TOTPCode(a.TOTPPending, time.Now()) != "000000" {
		mustContain(t, body, "Der Code ist ungültig")
	}
	_, body = c.post("/account", url.Values{"action": {"totp-confirm"}, "code": {security.TOTPCode(a.TOTPPending, time.Now())}})
	mustContain(t, body, "Zwei-Faktor-Authentifizierung ist jetzt aktiv")
	// The current session stays valid even though the auth stamp changed.
	if _, body := c.get("/dashboard"); !strings.Contains(body, "Übersicht") {
		t.Fatal("session lost after enabling 2FA")
	}

	// New login requires the second factor.
	n := env.client()
	body = n.login("admin", "admin-pass-123")
	mustContain(t, body, "Code aus deiner Authenticator-App")
	if code, _ := n.get("/dashboard"); code != 200 {
		t.Fatal(code)
	}
	if _, body := n.get("/dashboard"); strings.Contains(body, "Übersicht") {
		t.Fatal("logged in without 2FA code")
	}
	n.get("/login/2fa")
	a, _ = env.srv.admins.Get("admin")
	// The code used for confirmation must not be accepted again (replay); use the next time step.
	next := security.TOTPCode(a.TOTPSecret, time.Now().Add(30*time.Second))
	_, body = n.post("/login/2fa", url.Values{"code": {next}, "next": {"/users"}})
	mustContain(t, body, "alice", "Neuer Benutzer")

	// A third client cannot reuse the same code (replay protection).
	r := env.client()
	r.login("admin", "admin-pass-123")
	_, body = r.post("/login/2fa", url.Values{"code": {next}})
	mustContain(t, body, "ungültig oder wurde bereits verwendet")
}

func TestLoginLockout(t *testing.T) {
	env := newTestEnv(t, "")
	c := env.client()
	for i := 0; i < 5; i++ {
		c.login("admin", "nope")
	}
	body := c.login("admin", "admin-pass-123")
	mustContain(t, body, "Zu viele Fehlversuche")
}

func TestOpenRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "/dashboard",
		"/users":           "/users",
		"//evil.example":   "/dashboard",
		"/\\evil.example":  "/dashboard",
		"https://evil.com": "/dashboard",
		"/x\r\nSet-Cookie": "/dashboard",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublish(t *testing.T) {
	var got map[string]any
	var auth string
	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			_, _ = w.Write([]byte(`{"healthy":true}`))
			return
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["topic"] == "secret" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":40301,"http":403,"error":"forbidden"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"abc123","event":"message"}`))
	}))
	defer ntfySrv.Close()
	env := newTestEnv(t, ntfySrv.URL)
	c := env.client()
	c.login("admin", "admin-pass-123")
	c.get("/publish")

	_, body := c.post("/publish", url.Values{"topic": {"alerts"}, "title": {"Grüße"}, "message": {"Hallo Welt"},
		"priority": {"4"}, "tags": {"warning, backup"}, "token": {"tk_abc"}})
	mustContain(t, body, "Nachricht an „alerts“ gesendet (ID abc123)")
	if got["title"] != "Grüße" || got["priority"] != float64(4) || auth != "Bearer tk_abc" {
		t.Fatalf("published: %v auth=%q", got, auth)
	}
	if tags, _ := got["tags"].([]any); len(tags) != 2 || tags[1] != "backup" {
		t.Fatalf("tags: %v", got["tags"])
	}

	code, body := c.post("/publish", url.Values{"topic": {"secret"}, "message": {"x"}, "priority": {"3"}})
	if code != http.StatusBadGateway {
		t.Fatalf("status %d", code)
	}
	mustContain(t, body, "Keine Berechtigung", `value="secret"`)

	code, _ = c.post("/publish", url.Values{"topic": {"../x"}, "message": {"x"}, "priority": {"3"}})
	if code != http.StatusBadRequest {
		t.Fatalf("invalid topic accepted: %d", code)
	}
}

func TestActivityChart(t *testing.T) {
	now := time.Date(2026, 10, 6, 15, 0, 0, 0, time.Local)
	evs := []store.AuditEvent{
		{Time: now.Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)},
		{Time: now.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)},
		{Time: now.AddDate(0, 0, -3).UTC().Format(time.RFC3339Nano)},
		{Time: now.AddDate(0, 0, -30).UTC().Format(time.RFC3339Nano)},
	}
	c := buildActivityChart(evs, 14, now)
	if c.Total != 3 || len(c.Bars) != 14 || c.Bars[13].Count != 2 || c.Bars[10].Count != 1 || !c.Bars[13].Today {
		t.Fatalf("chart: total=%d bars=%+v", c.Total, c.Bars)
	}
	if step, top := niceScale(7); step != 2 || top != 8 {
		t.Fatalf("niceScale(7) = %d, %d", step, top)
	}
}
