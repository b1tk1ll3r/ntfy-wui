package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

// NewToken returns a random URL-safe token with 32 bytes of entropy.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TokensEqual compares two secret tokens in constant time.
func TokensEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
