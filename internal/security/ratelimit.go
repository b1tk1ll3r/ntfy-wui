package security

import (
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter is a simple token bucket limiter per key.
type RateLimiter struct {
	mu        sync.Mutex
	capacity  float64
	refillPer float64 // tokens/sec
	ttl       time.Duration
	buckets   map[string]*bucket
	lastGC    time.Time
}

func NewRateLimiter(capacity int, refillPerSec float64, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		capacity:  float64(capacity),
		refillPer: refillPerSec,
		ttl:       ttl,
		buckets:   map[string]*bucket{},
		lastGC:    time.Now(),
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if now.Sub(rl.lastGC) > rl.ttl {
		for k, v := range rl.buckets {
			if now.Sub(v.last) > rl.ttl {
				delete(rl.buckets, k)
			}
		}
		rl.lastGC = now
	}
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rl.capacity, last: now}
		rl.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rl.refillPer
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Middleware(keyFn func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				key = "anon"
			}
			if !rl.Allow(key) {
				w.Header().Set("Retry-After", "2")
				http.Error(w, "Zu viele Anfragen – bitte kurz warten.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// FailureLimiter locks a key after too many failures within a time window
// (used for login brute-force protection).
type FailureLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	lockout time.Duration
	entries map[string]*failEntry
}

type failEntry struct {
	count       int
	first       time.Time
	lockedUntil time.Time
}

func NewFailureLimiter(max int, window, lockout time.Duration) *FailureLimiter {
	return &FailureLimiter{max: max, window: window, lockout: lockout, entries: map[string]*failEntry{}}
}

// Locked reports whether key is currently locked and for how long.
func (f *FailureLimiter) Locked(key string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.entries[key]
	if e == nil {
		return false, 0
	}
	if d := time.Until(e.lockedUntil); d > 0 {
		return true, d
	}
	return false, 0
}

// Fail records a failure for key.
func (f *FailureLimiter) Fail(key string) {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.entries) > 10000 {
		for k, e := range f.entries {
			if now.Sub(e.first) > f.window && now.After(e.lockedUntil) {
				delete(f.entries, k)
			}
		}
	}
	e := f.entries[key]
	if e == nil || now.Sub(e.first) > f.window {
		e = &failEntry{first: now}
		f.entries[key] = e
	}
	e.count++
	if e.count >= f.max {
		e.lockedUntil = now.Add(f.lockout)
		e.count = 0
		e.first = now
	}
}

// Reset clears the failures of key (e.g. after a successful login).
func (f *FailureLimiter) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, key)
}
