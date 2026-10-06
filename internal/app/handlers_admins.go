package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yourorg/ntfywui/internal/ntfy"
	"github.com/yourorg/ntfywui/internal/security"
	"github.com/yourorg/ntfywui/internal/store"
)

func (s *Server) handleAdmins(w http.ResponseWriter, r *http.Request) {
	s.page(w, r, http.StatusOK, "admins", Page{
		Title:    "WebUI-Admins",
		Subtitle: "Wer darf diese Oberfläche benutzen?",
		Nav:      "admins",
		Admin:    adminFrom(r),
		Data:     s.admins.List(),
	})
}

func (s *Server) handleAdminsPost(w http.ResponseWriter, r *http.Request) {
	me := adminFrom(r)
	username := strings.TrimSpace(r.PostFormValue("username"))
	action := r.PostFormValue("action")

	if action != "create" {
		if _, ok := s.admins.Get(username); !ok {
			s.fail(w, r, "/admins", store.ErrNotFound)
			return
		}
	}
	if username == me.Username && (action == "toggle-disable" || action == "delete" || action == "set-role") {
		s.fail(w, r, "/admins", "Du kannst dein eigenes Konto hier nicht deaktivieren, löschen oder herabstufen.")
		return
	}

	switch action {
	case "create":
		pass := r.PostFormValue("password")
		role := store.Role(r.PostFormValue("role"))
		switch {
		case !ntfy.ValidUsername(username):
			s.fail(w, r, "/admins", errBadUsername)
			return
		case len(pass) < minPasswordLen:
			s.fail(w, r, "/admins", "Das Passwort muss mindestens 8 Zeichen lang sein.")
			return
		case !role.Valid():
			s.fail(w, r, "/admins", "Ungültige Rolle.")
			return
		}
		err := s.admins.Create(store.Admin{Username: username, Role: role, PassHash: security.HashPassword(pass)})
		if err != nil {
			s.fail(w, r, "/admins", err)
			return
		}
		s.auditEvent(r, "webui_admin_create", username, map[string]string{"role": string(role)})
		s.done(w, r, "/admins", "Admin „"+username+"“ wurde angelegt.")

	case "set-role":
		role := store.Role(r.PostFormValue("role"))
		if !role.Valid() {
			s.fail(w, r, "/admins", "Ungültige Rolle.")
			return
		}
		if !s.updateAdmin(w, r, username, func(a *store.Admin) error { a.Role = role; return nil }) {
			return
		}
		s.auditEvent(r, "webui_admin_set_role", username, map[string]string{"role": string(role)})
		s.done(w, r, "/admins", "Rolle von „"+username+"“ ist jetzt "+roleLabel(role)+".")

	case "set-pass":
		pass := r.PostFormValue("password")
		if len(pass) < minPasswordLen {
			s.fail(w, r, "/admins", "Das Passwort muss mindestens 8 Zeichen lang sein.")
			return
		}
		hash := security.HashPassword(pass)
		if !s.updateAdmin(w, r, username, func(a *store.Admin) error { a.PassHash = hash; return nil }) {
			return
		}
		s.auditEvent(r, "webui_admin_set_pass", username, nil)
		s.done(w, r, "/admins", "Passwort von „"+username+"“ wurde gesetzt. Bestehende Sitzungen wurden beendet.")

	case "toggle-disable":
		var disabled bool
		if !s.updateAdmin(w, r, username, func(a *store.Admin) error { a.Disabled = !a.Disabled; disabled = a.Disabled; return nil }) {
			return
		}
		s.auditEvent(r, "webui_admin_toggle_disable", username, map[string]string{"disabled": boolStr(disabled)})
		if disabled {
			s.done(w, r, "/admins", "„"+username+"“ wurde deaktiviert.")
		} else {
			s.done(w, r, "/admins", "„"+username+"“ wurde aktiviert.")
		}

	case "2fa-reset":
		if !s.updateAdmin(w, r, username, func(a *store.Admin) error {
			a.TOTPSecret, a.TOTPPending, a.TOTPLast = "", "", 0
			return nil
		}) {
			return
		}
		s.auditEvent(r, "webui_admin_2fa_disable", username, nil)
		s.done(w, r, "/admins", "2FA von „"+username+"“ wurde zurückgesetzt. Die Einrichtung erfolgt unter „Mein Konto“.")

	case "delete":
		if err := s.admins.Delete(username); err != nil {
			s.fail(w, r, "/admins", err)
			return
		}
		s.auditEvent(r, "webui_admin_delete", username, nil)
		s.done(w, r, "/admins", "Admin „"+username+"“ wurde gelöscht.")

	default:
		s.fail(w, r, "/admins", "Unbekannte Aktion.")
	}
}

func (s *Server) updateAdmin(w http.ResponseWriter, r *http.Request, username string, fn func(a *store.Admin) error) bool {
	if _, err := s.admins.Update(username, fn); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			s.fail(w, r, "/admins", err.Error()+".")
		} else {
			s.fail(w, r, "/admins", err)
		}
		return false
	}
	return true
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
