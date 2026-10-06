package security

import (
	"net"
	"net/http"
	"strings"
)

type RealIPConfig struct {
	TrustedProxies []*net.IPNet
}

func (c RealIPConfig) trusted(ip net.IP) bool {
	for _, n := range c.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsTrusted reports whether remoteAddr (host:port or host) is a trusted proxy.
func (c RealIPConfig) IsTrusted(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && c.trusted(ip)
}

// RealIP returns the best-effort client IP.
//
// X-Forwarded-For is only honored when the direct peer is a trusted proxy.
// The header is walked from right to left and the first address that is not
// a trusted proxy is returned, so a client cannot spoof its address by
// sending its own X-Forwarded-For header.
func RealIP(r *http.Request, cfg RealIPConfig) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !cfg.IsTrusted(r.RemoteAddr) {
		return host
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		parts := strings.Split(strings.Join(xff, ","), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip == nil {
				break
			}
			if !cfg.trusted(ip) || i == 0 {
				return ip.String()
			}
		}
	}
	if xrip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xrip != nil {
		return xrip.String()
	}
	return host
}
