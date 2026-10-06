package store

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditEvent struct {
	Time   string            `json:"time"`
	Actor  string            `json:"actor"`
	IP     string            `json:"ip,omitempty"`
	UA     string            `json:"ua,omitempty"`
	Action string            `json:"action"`
	Target string            `json:"target,omitempty"`
	Meta   map[string]string `json:"meta,omitempty"`
}

// When parses the event time.
func (e AuditEvent) When() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, e.Time)
	return t
}

type AuditLog struct {
	mu   sync.Mutex
	path string
	fh   *os.File
}

// maxTailBytes limits how much of the log is read for display.
const maxTailBytes = 8 << 20

func NewAuditLog(path string) (*AuditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{path: path, fh: f}, nil
}

func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fh != nil {
		err := a.fh.Close()
		a.fh = nil
		return err
	}
	return nil
}

func (a *AuditLog) Append(ev AuditEvent) {
	ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(ev)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fh == nil {
		return
	}
	_, _ = a.fh.Write(append(b, '\n'))
}

// Tail returns the last max events, newest first (max <= 0: all within the read window).
func (a *AuditLog) Tail(max int) ([]AuditEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - maxTailBytes
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if off > 0 {
		// drop the (probably partial) first line
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	lines := bytes.Split(b, []byte{'\n'})
	capHint := len(lines)
	if max > 0 && max < capHint {
		capHint = max
	}
	out := make([]AuditEvent, 0, capHint)
	for i := len(lines) - 1; i >= 0 && (max <= 0 || len(out) < max); i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var ev AuditEvent
		if json.Unmarshal(lines[i], &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, nil
}

// Raw returns a reader for the whole log file (for export).
func (a *AuditLog) Raw() (io.ReadCloser, error) {
	return os.Open(a.path)
}
