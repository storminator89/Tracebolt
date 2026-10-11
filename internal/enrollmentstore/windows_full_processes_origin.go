package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type windowsFullProcessesIngressOriginKey struct{}
type windowsFullProcessesIngressOrigin struct{ origin string }

// WithWindowsFullProcessesIngressOrigin is installed solely from the configured,
// validated agent listener origin. Never pass a request Origin/Host/header here.
// Enrollment/UI and agent listeners may legitimately have different origins.
func WithWindowsFullProcessesIngressOrigin(ctx context.Context, origin string) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, windowsFullProcessesIngressOriginKey{}, windowsFullProcessesIngressOrigin{origin})
}
func fullProcessesIngressOrigin(ctx context.Context, profile string) (string, error) {
	if ctx == nil {
		return "", enrollmentstate.ErrProof
	}
	v, ok := ctx.Value(windowsFullProcessesIngressOriginKey{}).(windowsFullProcessesIngressOrigin)
	if !ok || !validWindowsFullProcessesOrigin(v.origin, profile) {
		return "", enrollmentstate.ErrProof
	}
	return v.origin, nil
}
func validWindowsFullProcessesOrigin(raw, profile string) bool {
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	} else if profile != "tls" {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || len(raw) == 0 || len(raw) > 512 || u.Scheme != scheme || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || raw != scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(raw, "\\%\r\n\t ") {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.String() != host {
			return false
		}
	} else {
		if len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return false
				}
			}
		}
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || scheme == "https" && p == "443" || scheme == "http" && p == "80" {
			return false
		}
		authority = net.JoinHostPort(host, p)
	}
	return authority == u.Host
}
