package security

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPasswordHashRoundtrip(t *testing.T) {
	h := HashPasswordPBKDF2("geheim", []byte("0123456789abcdef"), 1000)
	if ok, err := VerifyPasswordPBKDF2("geheim", h); !ok || err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if ok, _ := VerifyPasswordPBKDF2("falsch", h); ok {
		t.Fatal("wrong password accepted")
	}
	if HashIterations(h) != 1000 {
		t.Fatal("iterations")
	}
}

// Hashes created by the previous hand-written PBKDF2 implementation must still verify.
func TestLegacyHashCompatible(t *testing.T) {
	// pbkdf2_sha256, password "password", salt "salt", 1 iteration (RFC 7914 test vector, 32 bytes)
	h := "pbkdf2_sha256$1$c2FsdA$Eg-2z_z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs"
	if ok, err := VerifyPasswordPBKDF2("password", h); !ok || err != nil {
		t.Fatalf("legacy hash rejected: %v", err)
	}
}

func TestTOTPReplay(t *testing.T) {
	sec, _ := GenerateTOTPSecret()
	now := time.Now()
	code := TOTPCode(sec, now)
	step, ok := VerifyTOTPCounter(sec, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := VerifyTOTPCounter(sec, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if VerifyTOTP(sec, "000000", now) && TOTPCode(sec, now) != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestRealIP(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := RealIPConfig{TrustedProxies: []*net.IPNet{n}}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := RealIP(r, cfg); got != "1.2.3.4" {
		t.Errorf("untrusted peer: got %s", got)
	}

	r.RemoteAddr = "10.0.0.2:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 1.2.3.4, 10.0.0.9")
	if got := RealIP(r, cfg); got != "1.2.3.4" {
		t.Errorf("spoofed xff: got %s", got)
	}
}

func TestSessionRoundtrip(t *testing.T) {
	sm, err := NewSessionManager([]byte("0123456789abcdef0123456789abcdef"), "s", "/x", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	in := &Session{User: "admin", CSRF: "tok", Flash: &Flash{Kind: "success", Msg: "hi"}}
	if err := sm.Save(rec, in); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Path != "/x" || !cookie.HttpOnly {
		t.Errorf("cookie attrs: %+v", cookie)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	out, ok := sm.Get(r)
	if !ok || out.User != "admin" || out.Flash == nil || out.Flash.Msg != "hi" {
		t.Fatalf("roundtrip: %+v %v", out, ok)
	}

	// Tampered cookie must be rejected.
	cookie.Value = cookie.Value[:len(cookie.Value)-2] + "AA"
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	if _, ok := sm.Get(r); ok {
		t.Fatal("tampered cookie accepted")
	}
}

func TestFailureLimiter(t *testing.T) {
	f := NewFailureLimiter(3, time.Minute, time.Minute)
	for i := 0; i < 3; i++ {
		if locked, _ := f.Locked("k"); locked {
			t.Fatalf("locked too early at %d", i)
		}
		f.Fail("k")
	}
	if locked, _ := f.Locked("k"); !locked {
		t.Fatal("not locked after max failures")
	}
	f.Reset("k")
	if locked, _ := f.Locked("k"); locked {
		t.Fatal("still locked after reset")
	}
}
