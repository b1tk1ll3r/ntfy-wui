package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a base32 secret (160 bit) without padding.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// VerifyTOTP verifies a 6-digit code with ±1 step skew (30s step).
func VerifyTOTP(secretBase32, code string, now time.Time) bool {
	_, ok := VerifyTOTPCounter(secretBase32, code, now, 0)
	return ok
}

// VerifyTOTPCounter verifies a code and returns the matching time step.
// Steps <= lastUsed are rejected to prevent replay of an already used code.
func VerifyTOTPCounter(secretBase32, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	sec, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secretBase32, " ", "")))
	if err != nil {
		return 0, false
	}
	t := now.Unix() / 30
	for _, drift := range []int64{-1, 0, 1} {
		step := t + drift
		if step <= lastUsed {
			continue
		}
		if hmac.Equal([]byte(hotp(sec, uint64(step))), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

// TOTPCode returns the current code for a secret (used in tests).
func TOTPCode(secretBase32 string, now time.Time) string {
	sec, _ := b32.DecodeString(secretBase32)
	return hotp(sec, uint64(now.Unix()/30))
}

// OTPAuthURI builds the otpauth:// URI understood by authenticator apps.
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func hotp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	bin := (int(sum[off])&0x7f)<<24 |
		(int(sum[off+1])&0xff)<<16 |
		(int(sum[off+2])&0xff)<<8 |
		(int(sum[off+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1000000)
}
