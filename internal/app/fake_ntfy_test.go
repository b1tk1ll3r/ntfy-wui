package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// fakeNtfy emulates the parts of the ntfy CLI used by ntfywui, including its
// habit of writing human readable output to stderr.
type fakeNtfy struct {
	mu      sync.Mutex
	users   map[string]*fakeUser
	tiers   []string
	nextTok int
	calls   [][]string
}

type fakeUser struct {
	name, role, tier, pass string
	grants                 map[string]string
	tokens                 []fakeToken
}

type fakeToken struct{ value, label, expires string }

func newFakeNtfy() *fakeNtfy {
	f := &fakeNtfy{users: map[string]*fakeUser{}, tiers: []string{"pro", "basic"}}
	f.users["*"] = &fakeUser{name: "*", role: "anonymous", tier: "none", grants: map[string]string{}}
	return f
}

func (f *fakeNtfy) addUser(name, role string, grants map[string]string) {
	if grants == nil {
		grants = map[string]string{}
	}
	f.users[name] = &fakeUser{name: name, role: role, tier: "none", grants: grants}
}

func (f *fakeNtfy) run(ctx context.Context, args []string, env map[string]string) (string, string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	fail := func(format string, a ...any) (string, string, int, error) {
		return "", "Error: " + fmt.Sprintf(format, a...) + "\n", 1, nil
	}
	ok := func(format string, a ...any) (string, string, int, error) {
		return "", fmt.Sprintf(format, a...) + "\n", 0, nil
	}
	if len(args) == 1 && args[0] == "--version" {
		return "ntfy 2.11.0 (abc123), runtime go1.22, built at 2024-01-01\n", "", 0, nil
	}
	var flags = map[string]string{}
	var pos []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "--") {
			k, v, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			flags[k] = v
		} else {
			pos = append(pos, a)
		}
	}
	user := func(n string) *fakeUser {
		if n == "everyone" {
			n = "*"
		}
		return f.users[n]
	}
	switch args[0] {
	case "user":
		sub, pos := pos[0], pos[1:]
		switch sub {
		case "list":
			return "", f.userList(), 0, nil
		case "add":
			if f.users[pos[0]] != nil {
				return fail("user %s already exists", pos[0])
			}
			role := flags["role"]
			if role == "" {
				role = "user"
			}
			f.users[pos[0]] = &fakeUser{name: pos[0], role: role, tier: "none", pass: env["NTFY_PASSWORD"], grants: map[string]string{}}
			return ok("user %s added with role %s", pos[0], role)
		case "del":
			if user(pos[0]) == nil {
				return fail("user %s does not exist", pos[0])
			}
			delete(f.users, pos[0])
			return ok("user %s removed", pos[0])
		case "change-pass":
			u := user(pos[0])
			if u == nil {
				return fail("user %s does not exist", pos[0])
			}
			u.pass = env["NTFY_PASSWORD"]
			return ok("changed password for user %s", pos[0])
		case "change-role":
			u := user(pos[0])
			if u == nil {
				return fail("user %s does not exist", pos[0])
			}
			u.role = pos[1]
			if u.role == "admin" {
				u.grants = map[string]string{}
			}
			return ok("changed role for user %s to %s", pos[0], pos[1])
		case "change-tier":
			u := user(pos[0])
			if u == nil {
				return fail("user %s does not exist", pos[0])
			}
			if pos[1] != "none" && !contains(f.tiers, pos[1]) {
				return fail("tier %s does not exist", pos[1])
			}
			u.tier = pos[1]
			return ok("changed tier for user %s to %s", pos[0], pos[1])
		}
	case "access":
		if _, reset := flags["reset"]; reset {
			u := user(pos[0])
			if u == nil {
				return fail("user %s does not exist", pos[0])
			}
			if len(pos) > 1 {
				delete(u.grants, pos[1])
			} else {
				u.grants = map[string]string{}
			}
			return ok("reset access for user %s", pos[0])
		}
		u := user(pos[0])
		if u == nil {
			return fail("user %s does not exist", pos[0])
		}
		if u.role == "admin" {
			return fail("user %s is an admin user, access control entries have no effect", pos[0])
		}
		u.grants[pos[1]] = pos[2]
		return ok("granted %s access to topic %s", pos[2], pos[1])
	case "token":
		sub, pos := pos[0], pos[1:]
		switch sub {
		case "list":
			var b strings.Builder
			for _, u := range f.sortedUsers() {
				if u.name == "*" || (len(pos) > 0 && pos[0] != u.name) {
					continue
				}
				if len(u.tokens) == 0 {
					fmt.Fprintf(&b, "user %s has no access tokens\n", u.name)
					continue
				}
				fmt.Fprintf(&b, "user %s\n", u.name)
				for _, t := range u.tokens {
					label := ""
					if t.label != "" {
						label = " (" + t.label + ")"
					}
					exp := "never expires"
					if t.expires != "" {
						exp = "expires 31 Dec 26 12:00 UTC"
					}
					fmt.Fprintf(&b, "- %s%s, %s, accessed from 0.0.0.0 at 01 Jan 70 00:00 UTC\n", t.value, label, exp)
				}
			}
			return "", b.String(), 0, nil
		case "add":
			u := user(pos[0])
			if u == nil {
				return fail("user %s does not exist", pos[0])
			}
			f.nextTok++
			tok := fmt.Sprintf("tk_%029d", f.nextTok)
			u.tokens = append(u.tokens, fakeToken{value: tok, label: flags["label"], expires: flags["expires"]})
			return ok("token %s created for user %s, never expires", tok, pos[0])
		case "remove":
			u := user(pos[0])
			if u == nil {
				return fail("user %s does not exist", pos[0])
			}
			for i, t := range u.tokens {
				if t.value == pos[1] {
					u.tokens = append(u.tokens[:i], u.tokens[i+1:]...)
					return ok("token %s for user %s removed", pos[1], pos[0])
				}
			}
			return fail("token does not exist")
		}
	case "tier":
		var b strings.Builder
		for _, t := range f.tiers {
			fmt.Fprintf(&b, "tier %s (id: ti_%s)\n- Name: %s\n", t, t, strings.ToUpper(t))
		}
		return "", b.String(), 0, nil
	}
	return fail("unknown command %v", args)
}

func (f *fakeNtfy) sortedUsers() []*fakeUser {
	var us []*fakeUser
	for _, u := range f.users {
		us = append(us, u)
	}
	sort.Slice(us, func(i, j int) bool { return us[i].name < us[j].name })
	return us
}

func (f *fakeNtfy) userList() string {
	var b strings.Builder
	for _, u := range f.sortedUsers() {
		fmt.Fprintf(&b, "user %s (role: %s, tier: %s)\n", u.name, u.role, u.tier)
		if u.role == "admin" {
			b.WriteString("- read-write access to all topics (admin role)\n")
		} else if len(u.grants) > 0 {
			var topics []string
			for t := range u.grants {
				topics = append(topics, t)
			}
			sort.Strings(topics)
			for _, t := range topics {
				switch u.grants[t] {
				case "read-write":
					fmt.Fprintf(&b, "- read-write access to topic %s\n", t)
				case "read-only":
					fmt.Fprintf(&b, "- read-only access to topic %s\n", t)
				case "write-only":
					fmt.Fprintf(&b, "- write-only access to topic %s\n", t)
				default:
					fmt.Fprintf(&b, "- no access to topic %s\n", t)
				}
			}
		} else {
			b.WriteString("- no topic-specific permissions\n")
		}
		if u.name == "*" {
			b.WriteString("- no access to any (other) topics (server config)\n")
		}
	}
	return b.String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
