package app

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/ntfywui/internal/security"
	"github.com/yourorg/ntfywui/internal/store"
)

const pendingTTL = 5 * time.Minute

// safeNext only allows local, absolute paths (prevents open redirects like
// "//evil.example" or "/\evil.example").
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.HasPrefix(next, "/\\") || strings.ContainsAny(next, "\r\n") {
		return "/dashboard"
	}
	return next
}

type loginData struct {
	Next      string
	Username  string
	Bootstrap bool
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentAdmin(r); ok {
		http.Redirect(w, r, s.abs(safeNext(r.URL.Query().Get("next"))), http.StatusFound)
		return
	}
	s.page(w, r, http.StatusOK, "login", Page{
		Title: "Anmelden",
		Data: loginData{
			Next:      safeNext(r.URL.Query().Get("next")),
			Bootstrap: s.admins.Count() == 0,
		},
	})
}

func (s *Server) loginLocked(ip, user string) (bool, time.Duration) {
	if locked, d := s.loginFails.Locked("ip:" + ip); locked {
		return true, d
	}
	return s.loginFails.Locked("user:" + strings.ToLower(user))
}

func (s *Server) loginFailed(r *http.Request, ip, user, reason string) {
	s.loginFails.Fail("ip:" + ip)
	if user != "" {
		s.loginFails.Fail("user:" + strings.ToLower(user))
	}
	s.audit.Append(store.AuditEvent{Actor: user, IP: ip, UA: r.UserAgent(), Action: "login_failed", Meta: map[string]string{"reason": reason}})
}

func lockedMsg(d time.Duration) string {
	return fmt.Sprintf("Zu viele Fehlversuche. Bitte in %d Minuten erneut versuchen.", int(d.Minutes())+1)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PostFormValue("username"))
	pass := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	ip := s.clientIP(r)
	back := "/login?next=" + urlQueryEscape(next)

	if locked, d := s.loginLocked(ip, user); locked {
		s.audit.Append(store.AuditEvent{Actor: user, IP: ip, UA: r.UserAgent(), Action: "login_locked"})
		s.fail(w, r, back, lockedMsg(d))
		return
	}
	a, err := s.admins.CheckPassword(user, pass)
	if err != nil {
		s.loginFailed(r, ip, user, "password")
		s.fail(w, r, back, "Benutzername oder Passwort falsch.")
		return
	}
	if a.HasTOTP() {
		// Password ok – ask for the second factor in a separate step.
		sess := &security.Session{
			CSRF:       security.NewToken(),
			Pending:    a.Username,
			PendingExp: time.Now().Add(pendingTTL).Unix(),
		}
		_ = s.sessions.Save(w, sess)
		http.Redirect(w, r, s.abs("/login/2fa?next="+urlQueryEscape(next)), http.StatusSeeOther)
		return
	}
	s.completeLogin(w, r, a, next)
}

func (s *Server) pendingUser(r *http.Request) (string, bool) {
	sess, ok := s.sessions.Get(r)
	if !ok || sess.Pending == "" || time.Now().Unix() > sess.PendingExp {
		return "", false
	}
	return sess.Pending, true
}

func (s *Server) handleLogin2FAForm(w http.ResponseWriter, r *http.Request) {
	user, ok := s.pendingUser(r)
	if !ok {
		http.Redirect(w, r, s.abs("/login"), http.StatusSeeOther)
		return
	}
	s.page(w, r, http.StatusOK, "login2fa", Page{
		Title: "Zwei-Faktor-Anmeldung",
		Data:  loginData{Next: safeNext(r.URL.Query().Get("next")), Username: user},
	})
}

func (s *Server) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	user, ok := s.pendingUser(r)
	if !ok {
		s.fail(w, r, "/login", "Die Anmeldung ist abgelaufen. Bitte erneut anmelden.")
		return
	}
	next := safeNext(r.PostFormValue("next"))
	ip := s.clientIP(r)
	back := "/login/2fa?next=" + urlQueryEscape(next)
	if locked, d := s.loginLocked(ip, user); locked {
		s.fail(w, r, "/login", lockedMsg(d))
		return
	}
	a, err := s.admins.CheckTOTP(user, r.PostFormValue("code"), false)
	if err != nil {
		s.loginFailed(r, ip, user, "totp")
		if errors.Is(err, store.ErrInvalidTOTP) {
			s.fail(w, r, back, "Der Code ist ungültig oder wurde bereits verwendet.")
		} else {
			s.fail(w, r, "/login", err)
		}
		return
	}
	if a.Disabled {
		s.fail(w, r, "/login", "Benutzername oder Passwort falsch.")
		return
	}
	s.completeLogin(w, r, a, next)
}

// completeLogin issues a fresh session (prevents session fixation).
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, a store.Admin, next string) {
	ip := s.clientIP(r)
	s.loginFails.Reset("user:" + strings.ToLower(a.Username))
	s.loginFails.Reset("ip:" + ip)
	s.admins.TouchLogin(a.Username)
	sess := &security.Session{
		User:  a.Username,
		Stamp: a.Stamp(),
		CSRF:  security.NewToken(),
	}
	_ = s.sessions.Save(w, sess)
	s.audit.Append(store.AuditEvent{Actor: a.Username, IP: ip, UA: r.UserAgent(), Action: "login_ok", Target: a.Username,
		Meta: map[string]string{"role": string(a.Role)}})
	http.Redirect(w, r, s.abs(next), http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if a, ok := s.currentAdmin(r); ok {
		s.audit.Append(store.AuditEvent{Actor: a.Username, IP: s.clientIP(r), UA: r.UserAgent(), Action: "logout"})
	}
	// Keep a fresh anonymous session so the login page can show the message.
	_ = s.sessions.Save(w, &security.Session{
		CSRF:  security.NewToken(),
		Flash: &security.Flash{Kind: "info", Msg: "Du wurdest abgemeldet."},
	})
	http.Redirect(w, r, s.abs("/login"), http.StatusSeeOther)
}
