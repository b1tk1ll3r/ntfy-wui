package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/yourorg/ntfywui/internal/store"
)

type dashboardData struct {
	NtfyErr       string
	Users         int
	NtfyAdmins    int
	Grants        int
	DefaultAccess string
	AnonGrants    int
	Tokens        int
	TokensKnown   bool
	WebAdmins     int
	NtfyVersion   string
	HealthChecked bool
	Healthy       bool
	HealthErr     string
	NtfyURL       string
	Recent        []store.AuditEvent
	Chart         *activityChart
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	d := dashboardData{NtfyURL: s.cfg.NtfyURL}

	healthc := make(chan error, 1)
	if s.publishEnabled() {
		d.HealthChecked = true
		go func() { healthc <- s.ntfyHealth(r.Context()) }()
	}

	users, err := s.ntfy.ListUsers(r.Context())
	if err != nil {
		d.NtfyErr = err.Error()
	}
	for _, u := range users {
		if u.IsEveryone() {
			d.DefaultAccess = u.DefaultAccess
			d.AnonGrants = len(u.Grants())
			d.Grants += len(u.Grants())
			continue
		}
		d.Users++
		if u.IsAdmin() {
			d.NtfyAdmins++
		}
		d.Grants += len(u.Grants())
	}
	if err == nil && admin.Role.AtLeast(store.RoleOperator) {
		if toks, err := s.ntfy.TokenList(r.Context(), ""); err == nil {
			d.Tokens, d.TokensKnown = len(toks), true
		}
	}
	d.NtfyVersion = s.ntfy.Version(r.Context())

	if admin.Role.AtLeast(store.RoleAdmin) {
		d.WebAdmins = s.admins.Count()
		if evs, err := s.audit.Tail(0); err == nil {
			d.Chart = buildActivityChart(evs, 14, time.Now())
			if len(evs) > 7 {
				evs = evs[:7]
			}
			d.Recent = evs
		}
	}
	if d.HealthChecked {
		if err := <-healthc; err != nil {
			d.HealthErr = err.Error()
		} else {
			d.Healthy = true
		}
	}

	s.page(w, r, http.StatusOK, "dashboard", Page{
		Title:    "Übersicht",
		Subtitle: "Status deines ntfy-Servers auf einen Blick",
		Nav:      "dashboard",
		Admin:    admin,
		Data:     d,
	})
}

func (s *Server) ntfyHealth(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.NtfyURL+"/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("nicht erreichbar")
	}
	defer resp.Body.Close()
	var body struct {
		Healthy bool `json:"healthy"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil || !body.Healthy {
		return fmt.Errorf("meldet Fehler (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// --- Activity chart (single series column chart, rendered as SVG) ---

type chartBar struct {
	SlotX, SlotW float64 // hover/hit area (full column height)
	Path         string  // column with 4px rounded top, square at the baseline
	Count        int
	Date         string
	Label        string // x-axis label (every other day)
	LabelX       float64
	Today        bool
}

type chartTick struct {
	Y     float64
	Label string
}

type activityChart struct {
	W, H         int
	PlotL, PlotR float64
	BaseY, TopY  float64
	PlotH        float64
	LabelY       float64
	TickX        float64
	Bars         []chartBar
	Ticks        []chartTick
	Total        int
	Days         int
}

var weekdays = [...]string{"So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"}

func buildActivityChart(evs []store.AuditEvent, days int, now time.Time) *activityChart {
	now = now.Local()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	start := today.AddDate(0, 0, -(days - 1))
	counts := make([]int, days)
	total := 0
	for _, e := range evs {
		t := e.When().Local()
		if t.Before(start) {
			continue
		}
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
		i := int(day.Sub(start).Hours()/24 + 0.5)
		if i >= 0 && i < days {
			counts[i]++
			total++
		}
	}
	maxCount := 0
	for _, c := range counts {
		maxCount = max(maxCount, c)
	}
	step, top := niceScale(maxCount)

	c := &activityChart{W: 640, H: 190, PlotL: 36, PlotR: 632, TopY: 12, BaseY: 158, LabelY: 178, Total: total, Days: days}
	plotH := c.BaseY - c.TopY
	c.PlotH, c.TickX = plotH, c.PlotL-8
	for v := 0; v <= top; v += step {
		c.Ticks = append(c.Ticks, chartTick{Y: c.BaseY - float64(v)/float64(top)*plotH, Label: fmt.Sprint(v)})
	}
	slot := (c.PlotR - c.PlotL) / float64(days)
	barW := math.Min(24, slot*0.62)
	for i, n := range counts {
		day := start.AddDate(0, 0, i)
		x := c.PlotL + float64(i)*slot
		b := chartBar{
			SlotX: x, SlotW: slot, Count: n,
			Date:   weekdays[day.Weekday()] + ", " + day.Format("02.01."),
			LabelX: x + slot/2,
			Today:  i == days-1,
		}
		if (days-1-i)%2 == 0 {
			b.Label = day.Format("02.01.")
		}
		if n > 0 {
			h := math.Max(float64(n)/float64(top)*plotH, 3)
			bx := x + (slot-barW)/2
			b.Path = roundedTopRect(bx, c.BaseY-h, barW, h, 4)
		}
		c.Bars = append(c.Bars, b)
	}
	return c
}

// niceScale returns a clean tick step and axis maximum (at most ~4 ticks).
func niceScale(maxVal int) (step, top int) {
	if maxVal <= 0 {
		return 1, 4
	}
	for _, mag := range []int{1, 10, 100, 1000, 10000, 100000} {
		for _, m := range []int{1, 2, 5} {
			step = m * mag
			if (maxVal+step-1)/step <= 4 {
				top = (maxVal + step - 1) / step * step
				return step, top
			}
		}
	}
	return maxVal, maxVal
}

func roundedTopRect(x, y, w, h, r float64) string {
	r = math.Min(r, math.Min(w/2, h))
	return fmt.Sprintf("M%.1f %.1fV%.1fQ%.1f %.1f %.1f %.1fH%.1fQ%.1f %.1f %.1f %.1fV%.1fZ",
		x, y+h, y+r, x, y, x+r, y, x+w-r, x+w, y, x+w, y+r, y+h)
}
