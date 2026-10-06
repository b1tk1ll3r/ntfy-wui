package ntfy

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const userListOutput = `user * (role: anonymous, tier: none)
- read-only access to topic announcements
- read-write access to all (other) topics (server config)
user phil (role: admin, tier: pro)
- read-write access to all topics (admin role)
user ben (role: user, tier: none, server config)
- read-write access to topic alerts_* (server config)
- write-only access to topic backups
- no access to topic secret
user carl (role: user, tier: none)
- no topic-specific permissions
`

func TestParseUsers(t *testing.T) {
	users := parseUsers(userListOutput)
	if len(users) != 4 {
		t.Fatalf("want 4 users, got %d", len(users))
	}
	if !users[0].IsEveryone() || users[0].DefaultAccess != PermReadWrite {
		t.Errorf("everyone: %+v", users[0])
	}
	if got := users[0].Access; len(got) != 1 || got[0].Topic != "announcements" || got[0].Perm != PermReadOnly {
		t.Errorf("everyone access: %+v", got)
	}
	ben := users[1]
	if ben.Username != "ben" || ben.Tier != "none" || !ben.Provisioned {
		t.Errorf("ben: %+v", ben)
	}
	want := []AccessEntry{
		{Topic: "alerts_*", Perm: PermReadWrite, Provisioned: true},
		{Topic: "backups", Perm: PermWriteOnly},
		{Topic: "secret", Perm: PermDeny},
	}
	if !reflect.DeepEqual(ben.Access, want) {
		t.Errorf("ben access:\n got %+v\nwant %+v", ben.Access, want)
	}
	if users[2].Username != "carl" || len(users[2].Access) != 0 {
		t.Errorf("carl: %+v", users[2])
	}
	phil := users[3]
	if !phil.IsAdmin() || phil.Tier != "pro" || len(phil.Access) != 1 || !phil.Access[0].All || len(phil.Grants()) != 0 {
		t.Errorf("phil: %+v", phil)
	}
}

func TestParseTokens(t *testing.T) {
	out := `user phil
- tk_7aq1j8bh9wbekpgn5rvn11nfupbn6 (my, label), expires 15 Mar 23 14:33 UTC, accessed from 1.2.3.4 at 13 Mar 23 10:33 UTC
- tk_u3ddgfhfu2e5ghbbmhzefnmjgysuv, never expires, accessed from 0.0.0.0 at 01 Jan 70 00:00 UTC
user ben has no access tokens
user carl
- tk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaa (ci), never expires, accessed from 10.0.0.1 at 01 Feb 24 08:00 UTC (server config)
`
	toks := parseTokens(out)
	if len(toks) != 3 {
		t.Fatalf("want 3 tokens, got %d: %+v", len(toks), toks)
	}
	want0 := Token{User: "phil", Token: "tk_7aq1j8bh9wbekpgn5rvn11nfupbn6", Label: "my, label", Expires: "15 Mar 23 14:33 UTC", LastOrigin: "1.2.3.4", LastAccess: "13 Mar 23 10:33 UTC"}
	if toks[0] != want0 {
		t.Errorf("tok0:\n got %+v\nwant %+v", toks[0], want0)
	}
	if toks[1].Label != "" || toks[1].Expires != "nie" || toks[1].LastOrigin != "" {
		t.Errorf("tok1: %+v", toks[1])
	}
	if toks[2].User != "carl" || toks[2].Label != "ci" || !toks[2].Provisioned || toks[2].LastOrigin != "10.0.0.1" {
		t.Errorf("tok2: %+v", toks[2])
	}
	if m := toks[0].Masked(); !strings.HasPrefix(m, "tk_7aq1") || !strings.HasSuffix(m, "pbn6") {
		t.Errorf("masked: %s", m)
	}
}

func TestValidation(t *testing.T) {
	for _, s := range []string{"phil", "a.b+c@d", "_x"} {
		if !ValidUsername(s) {
			t.Errorf("username %q should be valid", s)
		}
	}
	for _, s := range []string{"", "-rf", "--role=admin", "a b", "ä", "*"} {
		if ValidUsername(s) {
			t.Errorf("username %q should be invalid", s)
		}
	}
	if !ValidTopicPattern("alerts_*") || ValidTopicPattern("-x") || ValidTopic("a*") {
		t.Error("topic validation")
	}
	if p, ok := NormalizePerm("RO"); !ok || p != PermReadOnly {
		t.Error("normalize perm")
	}
}

func TestRunPassesConfigAndPassword(t *testing.T) {
	var gotArgs []string
	var gotEnv map[string]string
	c := &Client{Config: "/etc/ntfy/server.yml"}
	c.run = func(ctx context.Context, args []string, env map[string]string) (string, string, int, error) {
		gotArgs, gotEnv = args, env
		return "", "user ben added with role user\n", 0, nil
	}
	if err := c.AddUser(context.Background(), "ben", "user", "", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotArgs, []string{"user", "add", "--role=user", "ben"}) {
		t.Errorf("args: %v", gotArgs)
	}
	if gotEnv["NTFY_PASSWORD"] != "s3cret" || gotEnv["NTFY_CONFIG_FILE"] != "/etc/ntfy/server.yml" {
		t.Errorf("env: %v", gotEnv)
	}
}

func TestExecErrorMessage(t *testing.T) {
	c := &Client{}
	c.run = func(ctx context.Context, args []string, env map[string]string) (string, string, int, error) {
		return "", "Error: user ben does not exist\n", 1, nil
	}
	err := c.DelUser(context.Background(), "ben")
	if err == nil || !strings.Contains(err.Error(), "user ben does not exist") {
		t.Fatalf("err: %v", err)
	}
}

func TestTokenAddParsesStderr(t *testing.T) {
	c := &Client{}
	c.run = func(ctx context.Context, args []string, env map[string]string) (string, string, int, error) {
		return "", "token tk_abcdefghijklmnopqrstuvwxyz123 created for user ben, never expires\n", 0, nil
	}
	tok, err := c.TokenAdd(context.Background(), "ben", "x", "")
	if err != nil || tok != "tk_abcdefghijklmnopqrstuvwxyz123" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
}
