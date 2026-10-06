package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yourorg/ntfywui/internal/ntfy"
	"github.com/yourorg/ntfywui/internal/store"
)

const minPasswordLen = 8

var errBadUsername = errors.New("Ungültiger Benutzername (erlaubt: Buchstaben, Ziffern und - _ . + @, max. 64 Zeichen, nicht mit '-' beginnend)")

type usersData struct {
	Users []ntfy.User
	Tiers []string
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	users, err := s.ntfy.ListUsers(r.Context())
	if err != nil {
		s.ntfyError(w, r, err)
		return
	}
	d := usersData{Users: users}
	if admin.Role.AtLeast(store.RoleOperator) {
		d.Tiers = s.ntfy.ListTiers(r.Context())
	}
	s.page(w, r, http.StatusOK, "users", Page{
		Title:    "Benutzer",
		Subtitle: "ntfy-Benutzerkonten, Rollen und Zugriffsrechte",
		Nav:      "users",
		Admin:    admin,
		Data:     d,
	})
}

type userData struct {
	User      ntfy.User
	Tokens    []ntfy.Token
	TokensErr string
	Tiers     []string
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	name := r.PathValue("name")
	u, found, err := s.ntfy.FindUser(r.Context(), name)
	if err != nil {
		s.ntfyError(w, r, err)
		return
	}
	if !found {
		s.renderError(w, r, http.StatusNotFound, "Benutzer nicht gefunden", "Der ntfy-Benutzer „"+name+"“ existiert nicht.")
		return
	}
	d := userData{User: u}
	if admin.Role.AtLeast(store.RoleOperator) && !u.IsEveryone() {
		d.Tokens, err = s.ntfy.TokenList(r.Context(), u.Username)
		if err != nil {
			d.TokensErr = err.Error()
		}
		d.Tiers = s.ntfy.ListTiers(r.Context())
	}
	s.page(w, r, http.StatusOK, "user", Page{
		Title: displayUser(u.Username),
		Nav:   "users",
		Admin: admin,
		Data:  d,
	})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	pass := r.PostFormValue("password")
	role := r.PostFormValue("role")
	tier := strings.TrimSpace(r.PostFormValue("tier"))
	switch {
	case !ntfy.ValidUsername(username):
		s.fail(w, r, "/users", errBadUsername)
		return
	case len(pass) < minPasswordLen:
		s.fail(w, r, "/users", "Das Passwort muss mindestens 8 Zeichen lang sein.")
		return
	case role != "user" && role != "admin":
		s.fail(w, r, "/users", "Ungültige Rolle.")
		return
	case tier != "" && tier != "none" && !ntfy.ValidTier(tier):
		s.fail(w, r, "/users", "Ungültiger Tier-Code.")
		return
	}
	if err := s.ntfy.AddUser(r.Context(), username, role, tier, pass); err != nil {
		s.fail(w, r, "/users", err)
		return
	}
	s.auditEvent(r, "ntfy_user_add", username, map[string]string{"role": role, "tier": tier})
	s.done(w, r, userPath(username), "Benutzer „"+username+"“ wurde angelegt.")
}

func (s *Server) handleUserAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	back := userPath(name)
	if !ntfy.ValidAccessUser(name) {
		s.fail(w, r, "/users", errBadUsername)
		return
	}
	isEveryone := name == ntfy.Everyone

	// Actions that are not available for the anonymous user.
	switch action {
	case "password", "role", "tier", "delete", "token-add", "token-remove":
		if isEveryone {
			s.fail(w, r, back, "Diese Aktion ist für den anonymen Benutzer nicht möglich.")
			return
		}
	}

	ctx := r.Context()
	switch action {
	case "password":
		pass := r.PostFormValue("password")
		if len(pass) < minPasswordLen {
			s.fail(w, r, back, "Das Passwort muss mindestens 8 Zeichen lang sein.")
			return
		}
		if err := s.ntfy.ChangePass(ctx, name, pass); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.auditEvent(r, "ntfy_user_change_pass", name, nil)
		s.done(w, r, back, "Passwort wurde geändert.")

	case "role":
		role := r.PostFormValue("role")
		if role != "user" && role != "admin" {
			s.fail(w, r, back, "Ungültige Rolle.")
			return
		}
		if err := s.ntfy.ChangeRole(ctx, name, role); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.auditEvent(r, "ntfy_user_change_role", name, map[string]string{"role": role})
		s.done(w, r, back, "Rolle wurde auf „"+role+"“ gesetzt.")

	case "tier":
		tier := strings.TrimSpace(r.PostFormValue("tier"))
		if tier == "" {
			tier = "none"
		}
		if tier != "none" && !ntfy.ValidTier(tier) {
			s.fail(w, r, back, "Ungültiger Tier-Code.")
			return
		}
		if err := s.ntfy.ChangeTier(ctx, name, tier); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.auditEvent(r, "ntfy_user_change_tier", name, map[string]string{"tier": tier})
		s.done(w, r, back, "Tier wurde auf „"+tier+"“ gesetzt.")

	case "delete":
		if err := s.ntfy.DelUser(ctx, name); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.auditEvent(r, "ntfy_user_del", name, nil)
		s.done(w, r, "/users", "Benutzer „"+name+"“ wurde gelöscht.")

	case "grant":
		s.grant(w, r, name, back)

	case "revoke":
		topic := r.PostFormValue("topic")
		if !ntfy.ValidTopicPattern(topic) {
			s.fail(w, r, back, "Ungültiges Topic.")
			return
		}
		if err := s.ntfy.ResetAccess(ctx, name, topic); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.auditEvent(r, "ntfy_access_revoke", name, map[string]string{"topic": topic})
		s.done(w, r, back, "Zugriff auf „"+topic+"“ wurde entfernt.")

	case "reset":
		if err := s.ntfy.ResetAccess(ctx, name, ""); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.auditEvent(r, "ntfy_access_reset", name, nil)
		s.done(w, r, back, "Alle Zugriffsrechte wurden zurückgesetzt.")

	case "token-add":
		s.tokenAdd(w, r, name, back)

	case "token-remove":
		s.tokenRemove(w, r, name, back)

	default:
		s.renderError(w, r, http.StatusNotFound, "Unbekannte Aktion", "Die Aktion „"+action+"“ gibt es nicht.")
	}
}

// grant handles the shared "grant access" form (user page and access page).
func (s *Server) grant(w http.ResponseWriter, r *http.Request, username, back string) {
	topic := strings.TrimSpace(r.PostFormValue("topic"))
	perm, ok := ntfy.NormalizePerm(r.PostFormValue("perm"))
	switch {
	case !ntfy.ValidAccessUser(username):
		s.fail(w, r, back, errBadUsername)
		return
	case !ntfy.ValidTopicPattern(topic):
		s.fail(w, r, back, "Ungültiges Topic (erlaubt: Buchstaben, Ziffern, - _ und * als Platzhalter, max. 64 Zeichen).")
		return
	case !ok:
		s.fail(w, r, back, "Ungültige Berechtigung.")
		return
	}
	if err := s.ntfy.GrantAccess(r.Context(), username, topic, perm); err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.auditEvent(r, "ntfy_access_grant", username, map[string]string{"topic": topic, "perm": perm})
	s.done(w, r, back, permLabel(perm)+" für „"+topic+"“ an "+displayUser(username)+" vergeben.")
}

// ntfyError renders a helpful page when the ntfy CLI cannot be used.
func (s *Server) ntfyError(w http.ResponseWriter, r *http.Request, err error) {
	s.cfg.Logger.Printf("ntfy cli: %v", err)
	s.renderError(w, r, http.StatusBadGateway, "ntfy-CLI nicht verfügbar", err.Error())
}
