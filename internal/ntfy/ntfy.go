// Package ntfy wraps the ntfy CLI (`ntfy user|access|token|tier ...`).
//
// Note: the ntfy CLI prints almost all human readable output (user lists,
// token lists, confirmations) to stderr, so parsers always look at the
// combined output of stdout and stderr.
package ntfy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Everyone is the special ntfy user name used for anonymous access.
const Everyone = "*"

// Permission values accepted by `ntfy access`.
const (
	PermReadWrite = "read-write"
	PermReadOnly  = "read-only"
	PermWriteOnly = "write-only"
	PermDeny      = "deny"
)

// Perms lists all permissions in display order.
var Perms = []string{PermReadWrite, PermReadOnly, PermWriteOnly, PermDeny}

type Client struct {
	Bin     string
	Config  string
	Timeout time.Duration

	// run can be replaced (SetRunner) to fake the CLI in tests.
	run RunFunc
}

// RunFunc executes the ntfy CLI with the given arguments and extra environment.
type RunFunc func(ctx context.Context, args []string, env map[string]string) (stdout, stderr string, exit int, err error)

// SetRunner replaces the CLI execution (used by tests and demos).
func (c *Client) SetRunner(fn RunFunc) { c.run = fn }

type User struct {
	Username    string
	Role        string
	Tier        string
	Provisioned bool
	Access      []AccessEntry
	// DefaultAccess is only set for the Everyone user (auth-default-access).
	DefaultAccess string
}

// IsEveryone reports whether this is the anonymous "*" user.
func (u User) IsEveryone() bool { return u.Username == Everyone }

// IsAdmin reports whether the user has the ntfy admin role.
func (u User) IsAdmin() bool { return u.Role == "admin" }

// Grants returns only topic-specific entries (without the admin "all topics" entry).
func (u User) Grants() []AccessEntry {
	var out []AccessEntry
	for _, a := range u.Access {
		if !a.All {
			out = append(out, a)
		}
	}
	return out
}

type AccessEntry struct {
	Topic       string
	Perm        string // read-write, read-only, write-only, deny
	Provisioned bool   // defined in server.yml, cannot be changed via CLI
	All         bool   // admin role: access to all topics
}

type Token struct {
	User        string
	Token       string
	Label       string
	Expires     string // "never" or formatted date
	LastOrigin  string
	LastAccess  string
	Provisioned bool
}

// Masked returns a shortened token for display, e.g. "tk_abcd…wxyz".
func (t Token) Masked() string {
	if len(t.Token) <= 12 {
		return t.Token
	}
	return t.Token[:7] + "…" + t.Token[len(t.Token)-4:]
}

// --- Validation (mirrors ntfy's own rules, plus: no leading '-' to avoid flag injection) ---

var (
	reUsername     = regexp.MustCompile(`^[_.+@a-zA-Z0-9][-_.+@a-zA-Z0-9]{0,63}$`)
	reTopic        = regexp.MustCompile(`^[_A-Za-z0-9][-_A-Za-z0-9]{0,63}$`)
	reTopicPattern = regexp.MustCompile(`^[_*A-Za-z0-9][-_*A-Za-z0-9]{0,63}$`)
	reTier         = regexp.MustCompile(`^[_A-Za-z0-9][-_A-Za-z0-9]{0,63}$`)
	reExpires      = regexp.MustCompile(`^[0-9A-Za-z: .-]{1,40}$`)
)

func ValidUsername(s string) bool     { return reUsername.MatchString(s) }
func ValidTopic(s string) bool        { return reTopic.MatchString(s) }
func ValidTopicPattern(s string) bool { return reTopicPattern.MatchString(s) }
func ValidTier(s string) bool         { return reTier.MatchString(s) }
func ValidExpires(s string) bool      { return reExpires.MatchString(s) }

// ValidAccessUser accepts regular user names and the anonymous user.
func ValidAccessUser(s string) bool { return s == Everyone || s == "everyone" || ValidUsername(s) }

// NormalizePerm maps the aliases accepted by ntfy to canonical names.
func NormalizePerm(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "read-write", "rw":
		return PermReadWrite, true
	case "read-only", "read", "ro":
		return PermReadOnly, true
	case "write-only", "write", "wo":
		return PermWriteOnly, true
	case "deny", "none", "no":
		return PermDeny, true
	}
	return "", false
}

func cliUser(u string) string {
	if u == Everyone {
		return "everyone"
	}
	return u
}

// --- Execution ---

// Run executes `ntfy args...`. The config file is passed via NTFY_CONFIG_FILE,
// because --config is a flag of the subcommands (user, access, token, tier),
// not a global flag.
func (c *Client) Run(ctx context.Context, args []string, env map[string]string) (string, string, int, error) {
	if c.Config != "" {
		merged := map[string]string{"NTFY_CONFIG_FILE": c.Config}
		for k, v := range env {
			merged[k] = v
		}
		env = merged
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	if c.run != nil {
		return c.run(ctx, args, env)
	}
	if c.Bin == "" {
		return "", "", 0, errors.New("ntfy binary not set")
	}
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	if len(env) > 0 {
		// Keep the inherited environment (PATH, TZ, HOME...) and add our values.
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return outb.String(), errb.String(), -1, errors.New("ntfy: Zeitüberschreitung beim CLI-Aufruf")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return outb.String(), errb.String(), ee.ExitCode(), nil
		}
		return outb.String(), errb.String(), -1, err
	}
	return outb.String(), errb.String(), 0, nil
}

// exec runs a command and returns the combined output or a readable error.
func (c *Client) exec(ctx context.Context, what string, args []string, env map[string]string) (string, error) {
	out, errOut, exit, err := c.Run(ctx, args, env)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	if exit != 0 {
		msg := strings.TrimSpace(errOut)
		if msg == "" {
			msg = strings.TrimSpace(out)
		}
		msg = strings.TrimPrefix(msg, "Error: ")
		msg = strings.TrimPrefix(msg, "error: ")
		if msg == "" {
			msg = fmt.Sprintf("exit code %d", exit)
		}
		return "", fmt.Errorf("%s fehlgeschlagen: %s", what, msg)
	}
	return out + "\n" + errOut, nil
}

// --- Users ---

var (
	reUserLine     = regexp.MustCompile(`^user\s+(\S+)\s+\(role:\s*([^,)]+),\s*tier:\s*([^,)]+)(,[^)]*)?\)`)
	reGrantLine    = regexp.MustCompile(`^-\s+(read-write|read-only|write-only|no)\s+access\s+to\s+topic\s+(\S+)(\s+\(server config\))?\s*$`)
	reDefaultLine  = regexp.MustCompile(`^-\s+(read-write|read-only|write-only|no)\s+access\s+to\s+(?:all|any)\s+\(other\)\s+topics`)
	reAdminAllLine = regexp.MustCompile(`^-\s+read-write\s+access\s+to\s+all\s+topics`)
)

func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	out, err := c.exec(ctx, "ntfy user list", []string{"user", "list"}, nil)
	if err != nil {
		return nil, err
	}
	return parseUsers(out), nil
}

// FindUser returns a single user from the user list.
func (c *Client) FindUser(ctx context.Context, username string) (User, bool, error) {
	users, err := c.ListUsers(ctx)
	if err != nil {
		return User{}, false, err
	}
	for _, u := range users {
		if u.Username == username {
			return u, true, nil
		}
	}
	return User{}, false, nil
}

func permFromText(s string) string {
	if s == "no" {
		return PermDeny
	}
	return s
}

func parseUsers(out string) []User {
	var users []User
	cur := -1
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if m := reUserLine.FindStringSubmatch(ln); m != nil {
			users = append(users, User{
				Username:    m[1],
				Role:        strings.TrimSpace(m[2]),
				Tier:        strings.TrimSpace(m[3]),
				Provisioned: strings.Contains(m[4], "server config"),
			})
			cur = len(users) - 1
			continue
		}
		if cur < 0 || !strings.HasPrefix(ln, "-") {
			continue
		}
		u := &users[cur]
		switch {
		case reAdminAllLine.MatchString(ln) && strings.Contains(ln, "admin role"):
			u.Access = append(u.Access, AccessEntry{Topic: "*", Perm: PermReadWrite, All: true})
		case reDefaultLine.MatchString(ln):
			u.DefaultAccess = permFromText(reDefaultLine.FindStringSubmatch(ln)[1])
		default:
			if m := reGrantLine.FindStringSubmatch(ln); m != nil {
				u.Access = append(u.Access, AccessEntry{
					Topic:       m[2],
					Perm:        permFromText(m[1]),
					Provisioned: m[3] != "",
				})
			}
		}
	}
	// Anonymous user first, then alphabetically.
	sort.SliceStable(users, func(i, j int) bool {
		if users[i].IsEveryone() != users[j].IsEveryone() {
			return users[i].IsEveryone()
		}
		return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
	})
	return users
}

func (c *Client) AddUser(ctx context.Context, username, role, tier, password string) error {
	args := []string{"user", "add"}
	if role != "" {
		args = append(args, "--role="+role)
	}
	args = append(args, username)
	if _, err := c.exec(ctx, "ntfy user add", args, map[string]string{"NTFY_PASSWORD": password}); err != nil {
		return err
	}
	if tier != "" && tier != "none" {
		return c.ChangeTier(ctx, username, tier)
	}
	return nil
}

func (c *Client) DelUser(ctx context.Context, username string) error {
	_, err := c.exec(ctx, "ntfy user del", []string{"user", "del", username}, nil)
	return err
}

func (c *Client) ChangePass(ctx context.Context, username, password string) error {
	_, err := c.exec(ctx, "ntfy user change-pass", []string{"user", "change-pass", username}, map[string]string{"NTFY_PASSWORD": password})
	return err
}

func (c *Client) ChangeRole(ctx context.Context, username, role string) error {
	_, err := c.exec(ctx, "ntfy user change-role", []string{"user", "change-role", username, role}, nil)
	return err
}

func (c *Client) ChangeTier(ctx context.Context, username, tier string) error {
	_, err := c.exec(ctx, "ntfy user change-tier", []string{"user", "change-tier", username, tier}, nil)
	return err
}

// --- Access ---

func (c *Client) GrantAccess(ctx context.Context, username, topic, perm string) error {
	_, err := c.exec(ctx, "ntfy access", []string{"access", cliUser(username), topic, perm}, nil)
	return err
}

// ResetAccess removes all grants of a user, or only the grant for topic if topic != "".
func (c *Client) ResetAccess(ctx context.Context, username, topic string) error {
	args := []string{"access", "--reset", cliUser(username)}
	if topic != "" {
		args = append(args, topic)
	}
	_, err := c.exec(ctx, "ntfy access --reset", args, nil)
	return err
}

// --- Tokens ---

var (
	reTokenUser = regexp.MustCompile(`^user\s+(\S+)\s*$`)
	reToken     = regexp.MustCompile(`\b(tk_[A-Za-z0-9]+)\b`)
)

// TokenList lists tokens of one user, or of all users if username is "".
func (c *Client) TokenList(ctx context.Context, username string) ([]Token, error) {
	args := []string{"token", "list"}
	if username != "" {
		args = append(args, username)
	}
	out, err := c.exec(ctx, "ntfy token list", args, nil)
	if err != nil {
		return nil, err
	}
	toks := parseTokens(out)
	if username != "" {
		for i := range toks {
			if toks[i].User == "" {
				toks[i].User = username
			}
		}
	}
	return toks, nil
}

// parseTokens parses lines like:
//
//	user phil
//	- tk_abc (my label), expires 15 Mar 23 14:33 UTC, accessed from 1.2.3.4 at 13 Mar 23 10:33 UTC
//	- tk_def, never expires, accessed from 0.0.0.0 at 01 Jan 70 00:00 UTC
func parseTokens(out string) []Token {
	var toks []Token
	curUser := ""
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if m := reTokenUser.FindStringSubmatch(ln); m != nil {
			curUser = m[1]
			continue
		}
		if !strings.HasPrefix(ln, "-") {
			continue
		}
		m := reToken.FindStringSubmatchIndex(ln)
		if m == nil {
			continue
		}
		t := Token{User: curUser, Token: ln[m[2]:m[3]]}
		rest := ln[m[3]:]
		if strings.HasSuffix(rest, " (server config)") {
			t.Provisioned = true
			rest = strings.TrimSuffix(rest, " (server config)")
		}
		// Split "<label part>, <expires part>, accessed from <ip> at <date>"
		expIdx := strings.LastIndex(rest, ", never expires")
		if i := strings.LastIndex(rest, ", expires "); i > expIdx {
			expIdx = i
		}
		if expIdx >= 0 {
			head := strings.TrimSpace(rest[:expIdx])
			if strings.HasPrefix(head, "(") && strings.HasSuffix(head, ")") {
				t.Label = head[1 : len(head)-1]
			}
			tail := rest[expIdx+2:]
			expPart, accPart, _ := strings.Cut(tail, ", accessed from ")
			if expPart == "never expires" {
				t.Expires = "nie"
			} else {
				t.Expires = strings.TrimPrefix(expPart, "expires ")
			}
			if accPart != "" {
				origin, at, _ := strings.Cut(accPart, " at ")
				t.LastOrigin = origin
				t.LastAccess = at
				if origin == "0.0.0.0" || origin == "" {
					t.LastOrigin, t.LastAccess = "", ""
				}
			}
		}
		toks = append(toks, t)
	}
	return toks
}

func (c *Client) TokenAdd(ctx context.Context, username, label, expires string) (string, error) {
	args := []string{"token", "add"}
	if expires != "" {
		args = append(args, "--expires="+expires)
	}
	if label != "" {
		args = append(args, "--label="+label)
	}
	args = append(args, username)
	out, err := c.exec(ctx, "ntfy token add", args, nil)
	if err != nil {
		return "", err
	}
	m := reToken.FindStringSubmatch(out)
	if m == nil {
		return "", errors.New("Token wurde erstellt, konnte aber nicht aus der CLI-Ausgabe gelesen werden")
	}
	return m[1], nil
}

func (c *Client) TokenRemove(ctx context.Context, username, token string) error {
	_, err := c.exec(ctx, "ntfy token remove", []string{"token", "remove", username, token}, nil)
	return err
}

// --- Tiers & misc ---

var reTierLine = regexp.MustCompile(`^tier\s+(\S+)`)

// ListTiers returns the tier codes known to ntfy (best effort; empty on error).
func (c *Client) ListTiers(ctx context.Context) []string {
	out, err := c.exec(ctx, "ntfy tier list", []string{"tier", "list"}, nil)
	if err != nil {
		return nil
	}
	var tiers []string
	for _, ln := range strings.Split(out, "\n") {
		if m := reTierLine.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			tiers = append(tiers, m[1])
		}
	}
	return tiers
}

var reVersion = regexp.MustCompile(`\b(\d+\.\d+\.\d+)\b`)

// Version returns the ntfy CLI version (best effort; empty on error).
func (c *Client) Version(ctx context.Context) string {
	out, errOut, _, err := c.Run(ctx, []string{"--version"}, nil)
	if err != nil {
		return ""
	}
	if m := reVersion.FindStringSubmatch(out + errOut); m != nil {
		return m[1]
	}
	return ""
}
