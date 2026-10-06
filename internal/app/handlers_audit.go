package app

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/ntfywui/internal/store"
)

type auditData struct {
	Events []store.AuditEvent
	Limit  int
	Limits []int
	Query  string
	Kind   string
	Total  int
	Failed int
	Actors int
}

var auditLimits = []int{100, 250, 500, 1000}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 250
	}
	evs, err := s.audit.Tail(limit)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Audit-Log nicht lesbar", err.Error())
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	kind := r.URL.Query().Get("kind")
	d := auditData{Limit: limit, Limits: auditLimits, Query: r.URL.Query().Get("q"), Kind: kind}
	actors := map[string]bool{}
	for _, e := range evs {
		if kind != "" && actionKind(e.Action) != kind {
			continue
		}
		if q != "" && !auditMatches(e, q) {
			continue
		}
		d.Events = append(d.Events, e)
		if e.Action == "login_failed" || e.Action == "login_locked" {
			d.Failed++
		}
		if e.Actor != "" {
			actors[e.Actor] = true
		}
	}
	d.Total = len(d.Events)
	d.Actors = len(actors)
	s.page(w, r, http.StatusOK, "audit", Page{
		Title:    "Audit-Log",
		Subtitle: "Alle Änderungen und Anmeldungen, neueste zuerst",
		Nav:      "audit",
		Admin:    adminFrom(r),
		Data:     d,
	})
}

func auditMatches(e store.AuditEvent, q string) bool {
	hay := []string{e.Actor, e.IP, e.Action, actionLabel(e.Action), e.Target}
	for k, v := range e.Meta {
		hay = append(hay, k+"="+v)
	}
	return strings.Contains(strings.ToLower(strings.Join(hay, " ")), q)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	f, err := s.audit.Raw()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Audit-Log nicht lesbar", err.Error())
		return
	}
	defer f.Close()
	s.auditEvent(r, "audit_export", "", nil)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="ntfywui-audit-`+time.Now().Format("20060102-150405")+`.jsonl"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}
