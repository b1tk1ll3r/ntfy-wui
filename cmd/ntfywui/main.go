package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yourorg/ntfywui/internal/app"
)

// version is set at build time: -ldflags "-X main.version=1.2.3"
var version = "dev"

func main() {
	var (
		listenAddr   = flag.String("listen", envOr("NTFYWUI_LISTEN", ":8080"), "HTTP listen address")
		basePath     = flag.String("base-path", envOr("NTFYWUI_BASE_PATH", ""), "Base path prefix, e.g. /ntfywui (no trailing slash)")
		dataDir      = flag.String("data-dir", envOr("NTFYWUI_DATA_DIR", "/data"), "Data dir for admin store and audit log")
		secret       = flag.String("secret", envOr("NTFYWUI_SECRET", ""), "Secret key (base64 or raw, >=32 bytes) for sessions (required)")
		cookieSecure = flag.Bool("cookie-secure", envOrBool("NTFYWUI_COOKIE_SECURE", true), "Set Secure cookies (requires HTTPS)")
		trustProxy   = flag.String("trust-proxy", envOr("NTFYWUI_TRUST_PROXY", ""), "Comma-separated CIDRs of trusted reverse proxies for X-Forwarded-For")
		ntfyBin      = flag.String("ntfy-bin", envOr("NTFYWUI_NTFY_BIN", "/usr/bin/ntfy"), "Path to ntfy binary")
		ntfyConfig   = flag.String("ntfy-config", envOr("NTFYWUI_NTFY_CONFIG", "/etc/ntfy/server.yml"), "Path to ntfy server.yml")
		ntfyTimeout  = flag.Duration("ntfy-timeout", envOrDur("NTFYWUI_NTFY_TIMEOUT", 10*time.Second), "Timeout for ntfy CLI calls")
		ntfyURL      = flag.String("ntfy-url", envOr("NTFYWUI_NTFY_URL", ""), "Optional base URL of the ntfy server (enables publishing and health check), e.g. http://ntfy:80")
		genSecret    = flag.Bool("gen-secret", false, "Print a new random secret and exit")
		showVersion  = flag.Bool("version", false, "Print version and exit")
		healthcheck  = flag.Bool("healthcheck", false, "Check /healthz of a running instance and exit (for Docker HEALTHCHECK)")
	)
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("ntfywui", version)
		return
	case *genSecret:
		fmt.Println(generateSecret())
		return
	case *healthcheck:
		os.Exit(runHealthcheck(*listenAddr, strings.TrimRight(*basePath, "/")))
	}

	if *secret == "" {
		log.Fatal("NTFYWUI_SECRET is required (>=32 random bytes; generate one with: ntfywui -gen-secret)")
	}
	secKey := decodeSecret(*secret)
	if len(secKey) < 32 {
		log.Fatalf("secret too short: need at least 32 bytes, got %d (generate one with: ntfywui -gen-secret)", len(secKey))
	}

	var trusted []*net.IPNet
	for _, cidr := range strings.Split(*trustProxy, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("invalid trust-proxy CIDR %q: %v", cidr, err)
		}
		trusted = append(trusted, n)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	s, err := app.NewServer(app.Config{
		BasePath:       *basePath,
		DataDir:        *dataDir,
		Secret:         secKey,
		CookieSecure:   *cookieSecure,
		TrustedProxies: trusted,
		NtfyBin:        *ntfyBin,
		NtfyConfig:     *ntfyConfig,
		NtfyTimeout:    *ntfyTimeout,
		NtfyURL:        *ntfyURL,
		Version:        version,
		Logger:         logger,
	})
	if err != nil {
		logger.Fatalf("init: %v", err)
	}

	// Optional bootstrap admin (only if no admin exists yet).
	if u := strings.TrimSpace(os.Getenv("NTFYWUI_BOOTSTRAP_USER")); u != "" {
		p := os.Getenv("NTFYWUI_BOOTSTRAP_PASS")
		if len(p) < 8 {
			logger.Printf("bootstrap: NTFYWUI_BOOTSTRAP_PASS empty or shorter than 8 characters; skipping")
		} else if created, err := s.BootstrapAdmin(u, p); err != nil {
			logger.Printf("bootstrap admin: %v", err)
		} else if created {
			logger.Printf("bootstrap admin %q created – change the password after the first login", u)
		}
	}
	if !*cookieSecure {
		logger.Printf("WARNING: secure cookies disabled (NTFYWUI_COOKIE_SECURE=false) – only use this without HTTPS in a trusted network")
	}

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           s.Handler(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		logger.Printf("ntfywui %s listening on %s%s/", version, *listenAddr, s.BasePath())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Println("shutdown requested")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown error: %v", err)
	}
	_ = s.Close()
}

func runHealthcheck(listen, basePath string) int {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid listen address:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + basePath + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status", resp.StatusCode)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envOrBool(k string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	}
	return def
}

func envOrDur(k string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv(k))); err == nil {
		return d
	}
	return def
}

// decodeSecret accepts base64 (std/url, padded or not) or a raw string.
func decodeSecret(s string) []byte {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) >= 32 {
			return b
		}
	}
	return []byte(s)
}

func generateSecret() string {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
