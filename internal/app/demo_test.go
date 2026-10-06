package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yourorg/ntfywui/internal/security"
	"github.com/yourorg/ntfywui/internal/store"
)

// TestDemoServer runs the UI with a fake ntfy CLI and sample data for manual
// UI checks:  NTFYWUI_DEMO_ADDR=127.0.0.1:8099 go test ./internal/app -run TestDemoServer -v
// All requests are automatically logged in as "admin" unless ?anon=1 is given.
func TestDemoServer(t *testing.T) {
	addr := os.Getenv("NTFYWUI_DEMO_ADDR")
	if addr == "" {
		t.Skip("set NTFYWUI_DEMO_ADDR to run the demo server")
	}
	secs, _ := strconv.Atoi(os.Getenv("NTFYWUI_DEMO_SECONDS"))
	if secs <= 0 {
		secs = 600
	}

	dir := t.TempDir()
	writeDemoAudit(t, filepath.Join(dir, "audit.jsonl"))

	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":true,"id":"demo"}`))
	}))
	defer ntfySrv.Close()

	s, err := NewServer(Config{
		DataDir: dir, Secret: []byte("0123456789abcdef0123456789abcdef"),
		NtfyURL: ntfySrv.URL, Version: "2.0.0", Logger: log.New(os.Stdout, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeNtfy()
	fake.users["*"].grants = map[string]string{"announcements": "read-only", "status": "read-only"}
	fake.addUser("alice", "user", map[string]string{"alerts": "read-write", "backup_*": "write-only", "home_*": "read-only"})
	fake.addUser("bob", "user", map[string]string{"alerts": "read-only", "ci": "read-write", "deploy_*": "read-write", "metrics": "read-only", "secret": "deny"})
	fake.addUser("homeassistant", "user", map[string]string{"home_*": "read-write"})
	fake.addUser("phil", "admin", nil)
	fake.addUser("monitoring", "user", map[string]string{"uptime": "write-only"})
	fake.users["bob"].tier = "pro"
	fake.users["alice"].tokens = []fakeToken{{value: "tk_7aq1j8bh9wbekpgn5rvn11nfupbn6", label: "Android"}, {value: "tk_u3ddgfhfu2e5ghbbmhzefnmjgysuv", label: "Backup-Skript", expires: "30d"}}
	fake.users["homeassistant"].tokens = []fakeToken{{value: "tk_q8w7e6r5t4y3u2i1o9p8a7s6d5f4g", label: "Home Assistant"}}
	s.ntfy.SetRunner(fake.run)

	_, _ = s.admins.EnsureBootstrap("admin", "admin-pass-123")
	_ = s.admins.Create(store.Admin{Username: "jana", Role: store.RoleOperator, PassHash: security.HashPassword("x-pass-123"), LastLogin: time.Now().Add(-26 * time.Hour).Unix(), TOTPSecret: "JBSWY3DPEHPK3PXP"})
	_ = s.admins.Create(store.Admin{Username: "readonly", Role: store.RoleViewer, PassHash: security.HashPassword("x-pass-123"), Disabled: true})
	s.admins.TouchLogin("admin")
	a, _ := s.admins.Get("admin")

	rec := httptest.NewRecorder()
	_ = s.sessions.Save(rec, &security.Session{User: "admin", Stamp: a.Stamp(), CSRF: security.NewToken()})
	cookie := rec.Result().Cookies()[0]

	h := s.Handler()
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(cookie.Name); err != nil && r.URL.Query().Get("anon") == "" {
			r.AddCookie(cookie)
		}
		h.ServeHTTP(w, r)
	})}
	go func() {
		time.Sleep(time.Duration(secs) * time.Second)
		_ = srv.Close()
	}()
	fmt.Printf("demo server on http://%s/ for %ds\n", addr, secs)
	_ = srv.ListenAndServe()
}

func writeDemoAudit(t *testing.T, path string) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	actions := []struct{ action, actor, target string }{
		{"login_ok", "admin", "admin"}, {"ntfy_user_add", "admin", "monitoring"}, {"ntfy_access_grant", "jana", "alice"},
		{"ntfy_token_add", "jana", "homeassistant"}, {"login_failed", "root", ""}, {"ntfy_access_revoke", "admin", "bob"},
		{"ntfy_user_change_pass", "jana", "alice"}, {"ntfy_publish", "admin", "alerts"}, {"ntfy_token_remove", "admin", "bob"},
	}
	counts := []int{2, 0, 5, 3, 1, 0, 7, 4, 2, 9, 3, 1, 6, 4}
	now := time.Now()
	k := 0
	for d, n := range counts {
		for i := 0; i < n; i++ {
			a := actions[k%len(actions)]
			k++
			ts := now.AddDate(0, 0, -(len(counts) - 1 - d)).Add(-time.Duration(i*37) * time.Minute)
			if ts.After(now) {
				ts = now.Add(-time.Minute)
			}
			b, _ := json.Marshal(store.AuditEvent{Time: ts.UTC().Format(time.RFC3339Nano), Actor: a.actor, IP: "192.168.1.20", Action: a.action, Target: a.target,
				Meta: map[string]string{"topic": "alerts"}})
			_, _ = f.Write(append(b, '\n'))
		}
	}
}
