package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/yourorg/ntfywui/internal/ntfy"
)

type publishForm struct {
	Topic    string
	Title    string
	Message  string
	Priority int
	Tags     string
	Click    string
	Markdown bool
}

type publishData struct {
	Form    publishForm
	Err     string
	NtfyURL string
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if !s.publishEnabled() {
		s.renderError(w, r, http.StatusNotFound, "Senden nicht konfiguriert",
			"Setze NTFYWUI_NTFY_URL (z. B. http://ntfy:80), um Nachrichten aus der WebUI zu senden.")
		return
	}
	s.renderPublish(w, r, http.StatusOK, publishData{Form: publishForm{
		Topic:    r.URL.Query().Get("topic"),
		Priority: 3,
	}})
}

func (s *Server) renderPublish(w http.ResponseWriter, r *http.Request, status int, d publishData) {
	d.NtfyURL = s.cfg.NtfyURL
	s.page(w, r, status, "publish", Page{
		Title:    "Nachricht senden",
		Subtitle: "Testnachrichten und Benachrichtigungen an ein Topic schicken",
		Nav:      "publish",
		Admin:    adminFrom(r),
		Data:     d,
	})
}

func (s *Server) handlePublishPost(w http.ResponseWriter, r *http.Request) {
	if !s.publishEnabled() {
		s.renderError(w, r, http.StatusNotFound, "Senden nicht konfiguriert", "NTFYWUI_NTFY_URL ist nicht gesetzt.")
		return
	}
	f := publishForm{
		Topic:    strings.TrimSpace(r.PostFormValue("topic")),
		Title:    strings.TrimSpace(r.PostFormValue("title")),
		Message:  r.PostFormValue("message"),
		Tags:     strings.TrimSpace(r.PostFormValue("tags")),
		Click:    strings.TrimSpace(r.PostFormValue("click")),
		Markdown: r.PostFormValue("markdown") != "",
	}
	f.Priority, _ = strconv.Atoi(r.PostFormValue("priority"))
	token := strings.TrimSpace(r.PostFormValue("token"))

	errMsg := ""
	switch {
	case !ntfy.ValidTopic(f.Topic):
		errMsg = "Ungültiges Topic (erlaubt: Buchstaben, Ziffern, - und _, max. 64 Zeichen)."
	case strings.TrimSpace(f.Message) == "":
		errMsg = "Bitte eine Nachricht eingeben."
	case len(f.Message) > 4096:
		errMsg = "Die Nachricht ist zu lang (max. 4096 Zeichen)."
	case f.Priority < 1 || f.Priority > 5:
		errMsg = "Ungültige Priorität."
	case f.Click != "" && !validHTTPURL(f.Click):
		errMsg = "Der Klick-Link muss eine http(s)-URL sein."
	case token != "" && !strings.HasPrefix(token, "tk_"):
		errMsg = "Der Token muss mit „tk_“ beginnen."
	}
	if errMsg != "" {
		s.renderPublish(w, r, http.StatusBadRequest, publishData{Form: f, Err: errMsg})
		return
	}

	id, err := s.publish(r, f, token)
	if err != nil {
		s.renderPublish(w, r, http.StatusBadGateway, publishData{Form: f, Err: err.Error()})
		return
	}
	s.auditEvent(r, "ntfy_publish", f.Topic, map[string]string{"id": id, "priority": strconv.Itoa(f.Priority), "auth": fmt.Sprint(token != "")})
	s.done(w, r, "/publish?topic="+url.QueryEscape(f.Topic), "Nachricht an „"+f.Topic+"“ gesendet (ID "+id+").")
}

func validHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// publish sends a message using ntfy's JSON publishing API.
func (s *Server) publish(r *http.Request, f publishForm, token string) (string, error) {
	msg := map[string]any{
		"topic":    f.Topic,
		"message":  f.Message,
		"priority": f.Priority,
	}
	if f.Title != "" {
		msg["title"] = f.Title
	}
	if f.Click != "" {
		msg["click"] = f.Click
	}
	if f.Markdown {
		msg["markdown"] = true
	}
	if f.Tags != "" {
		var tags []string
		for _, t := range strings.Split(f.Tags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
		msg["tags"] = tags
	}
	body, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.cfg.NtfyURL+"/", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ntfy-Server nicht erreichbar: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden:
				return "", fmt.Errorf("Keine Berechtigung für dieses Topic (HTTP %d: %s). Gib ggf. einen Token mit Schreibrecht an.", resp.StatusCode, e.Error)
			}
			return "", fmt.Errorf("ntfy meldet HTTP %d: %s", resp.StatusCode, e.Error)
		}
		return "", fmt.Errorf("ntfy meldet HTTP %d", resp.StatusCode)
	}
	var ok struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &ok)
	return ok.ID, nil
}
