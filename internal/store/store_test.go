package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/yourorg/ntfywui/internal/security"
)

func TestAdminStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admins.json")
	s, err := NewAdminStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if created, _ := s.EnsureBootstrap("admin", "pass-1234"); !created {
		t.Fatal("bootstrap not created")
	}
	if created, _ := s.EnsureBootstrap("other", "pass-1234"); created {
		t.Fatal("bootstrap must only run on an empty store")
	}

	// Last active admin cannot be removed, disabled or demoted.
	if err := s.Delete("admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	if _, err := s.Update("admin", func(a *Admin) error { a.Role = RoleViewer; return nil }); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if a, _ := s.Get("admin"); a.Role != RoleAdmin {
		t.Fatal("failed update was not rolled back")
	}
	if err := s.Create(Admin{Username: "second", Role: RoleAdmin, PassHash: security.HashPasswordPBKDF2("x", []byte("salt"), 1000)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("admin"); err != nil {
		t.Fatalf("delete with another admin present: %v", err)
	}

	// Legacy hash (fewer iterations) is upgraded on successful login.
	if _, err := s.CheckPassword("second", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := s.CheckPassword("nobody", "x"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatal("unknown user")
	}
	a, err := s.CheckPassword("second", "x")
	if err != nil {
		t.Fatal(err)
	}
	if security.HashIterations(a.PassHash) != security.PBKDF2Iterations {
		t.Fatal("hash not upgraded")
	}

	// Data survives a reload.
	s2, err := NewAdminStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Count() != 1 || s2.List()[0].Username != "second" {
		t.Fatalf("reload: %+v", s2.List())
	}
}

func TestAuditTail(t *testing.T) {
	l, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, a := range []string{"a", "b", "c"} {
		l.Append(AuditEvent{Action: a})
	}
	evs, err := l.Tail(2)
	if err != nil || len(evs) != 2 || evs[0].Action != "c" || evs[1].Action != "b" {
		t.Fatalf("tail: %+v %v", evs, err)
	}
	if all, _ := l.Tail(0); len(all) != 3 {
		t.Fatalf("tail all: %d", len(all))
	}
}
