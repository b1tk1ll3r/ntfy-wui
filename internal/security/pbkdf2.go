package security

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// PBKDF2Iterations is used for new hashes (OWASP 2023 recommendation for PBKDF2-SHA256).
// Existing hashes keep their stored iteration count and are upgraded on next login.
const PBKDF2Iterations = 600_000

// HashPassword hashes a password with a random salt and the default iteration count.
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return HashPasswordPBKDF2(password, salt, PBKDF2Iterations)
}

// HashPasswordPBKDF2 returns "pbkdf2_sha256$<iter>$<salt>$<key>".
func HashPasswordPBKDF2(password string, salt []byte, iter int) string {
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		iter,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	)
}

// HashIterations returns the iteration count of an encoded hash (0 if unparsable).
func HashIterations(encoded string) int {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

func VerifyPasswordPBKDF2(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return false, fmt.Errorf("parse hash: expected 4 parts, got %d", len(parts))
	}
	if parts[0] != "pbkdf2_sha256" {
		return false, fmt.Errorf("unsupported algo %q", parts[0])
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, fmt.Errorf("parse hash iter: %v", err)
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("salt decode: %w", err)
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("key decode: %w", err)
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
