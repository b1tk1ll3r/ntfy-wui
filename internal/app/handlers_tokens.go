package app

import (
	"net/http"
	"strings"

	"github.com/yourorg/ntfywui/internal/ntfy"
	"github.com/yourorg/ntfywui/internal/security"
)

type tokensData struct {
	Users  []ntfy.User
	Tokens []ntfy.Token
	Err    string
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	users, err := s.ntfy.ListUsers(r.Context())
	if err != nil {
		s.ntfyError(w, r, err)
		return
	}
	d := tokensData{}
	for _, u := range users {
		if !u.IsEveryone() {
			d.Users = append(d.Users, u)
		}
	}
	d.Tokens, err = s.ntfy.TokenList(r.Context(), "")
	if err != nil {
		d.Err = err.Error()
	}
	s.page(w, r, http.StatusOK, "tokens", Page{
		Title:    "Access-Tokens",
		Subtitle: "Tokens für Skripte, Apps und Integrationen",
		Nav:      "tokens",
		Admin:    adminFrom(r),
		Data:     d,
	})
}

func (s *Server) handleTokensPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	if !ntfy.ValidUsername(username) {
		s.fail(w, r, "/tokens", errBadUsername)
		return
	}
	switch r.PostFormValue("action") {
	case "add":
		s.tokenAdd(w, r, username, "/tokens")
	case "remove":
		s.tokenRemove(w, r, username, "/tokens")
	default:
		s.fail(w, r, "/tokens", "Unbekannte Aktion.")
	}
}

func (s *Server) tokenAdd(w http.ResponseWriter, r *http.Request, username, back string) {
	label := strings.TrimSpace(r.PostFormValue("label"))
	expires := strings.TrimSpace(r.PostFormValue("expires"))
	if len(label) > 100 || strings.ContainsAny(label, "\r\n") {
		s.fail(w, r, back, "Das Label ist zu lang oder enthält ungültige Zeichen.")
		return
	}
	if expires != "" && !ntfy.ValidExpires(expires) {
		s.fail(w, r, back, "Ungültige Ablaufzeit (z. B. 24h, 30d, 2026-12-31).")
		return
	}
	tok, err := s.ntfy.TokenAdd(r.Context(), username, label, expires)
	if err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.auditEvent(r, "ntfy_token_add", username, map[string]string{"label": label, "expires": expires})
	s.flash(w, r, security.Flash{
		Kind:   "success",
		Msg:    "Token für „" + username + "“ erstellt. Kopiere ihn jetzt – er wird aus Sicherheitsgründen nur dieses eine Mal vollständig angezeigt.",
		Secret: tok,
	})
	http.Redirect(w, r, s.abs(back), http.StatusSeeOther)
}

func (s *Server) tokenRemove(w http.ResponseWriter, r *http.Request, username, back string) {
	token := strings.TrimSpace(r.PostFormValue("token"))
	if !strings.HasPrefix(token, "tk_") || strings.ContainsAny(token, " -") {
		s.fail(w, r, back, "Ungültiger Token.")
		return
	}
	if err := s.ntfy.TokenRemove(r.Context(), username, token); err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.auditEvent(r, "ntfy_token_remove", username, map[string]string{"token": ntfy.Token{Token: token}.Masked()})
	s.done(w, r, back, "Token wurde gelöscht.")
}
