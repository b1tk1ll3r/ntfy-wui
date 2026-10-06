package app

import (
	"net/http"
	"strings"

	"github.com/yourorg/ntfywui/internal/ntfy"
)

type accessRow struct {
	User  string
	Entry ntfy.AccessEntry
}

type accessData struct {
	Users         []ntfy.User
	Rows          []accessRow
	DefaultAccess string
	Preselect     string
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	users, err := s.ntfy.ListUsers(r.Context())
	if err != nil {
		s.ntfyError(w, r, err)
		return
	}
	d := accessData{Users: users, Preselect: r.URL.Query().Get("user")}
	for _, u := range users {
		if u.IsEveryone() {
			d.DefaultAccess = u.DefaultAccess
		}
		for _, a := range u.Grants() {
			d.Rows = append(d.Rows, accessRow{User: u.Username, Entry: a})
		}
	}
	s.page(w, r, http.StatusOK, "access", Page{
		Title:    "Zugriffsrechte",
		Subtitle: "Wer darf welche Topics lesen und schreiben?",
		Nav:      "access",
		Admin:    adminFrom(r),
		Data:     d,
	})
}

func (s *Server) handleAccessPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	switch r.PostFormValue("action") {
	case "grant":
		s.grant(w, r, username, "/access")
	case "revoke":
		topic := r.PostFormValue("topic")
		if !ntfy.ValidAccessUser(username) || !ntfy.ValidTopicPattern(topic) {
			s.fail(w, r, "/access", "Ungültiger Benutzer oder Topic.")
			return
		}
		if err := s.ntfy.ResetAccess(r.Context(), username, topic); err != nil {
			s.fail(w, r, "/access", err)
			return
		}
		s.auditEvent(r, "ntfy_access_revoke", username, map[string]string{"topic": topic})
		s.done(w, r, "/access", "Zugriff von "+displayUser(username)+" auf „"+topic+"“ wurde entfernt.")
	default:
		s.fail(w, r, "/access", "Unbekannte Aktion.")
	}
}
