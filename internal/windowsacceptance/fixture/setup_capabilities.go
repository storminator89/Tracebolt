package fixture

import (
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowssetup"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// A public, bodyless contract route only for the explicitly selected expanded
// fixture. It shares request/outage/lifetime limits with enrollment; never trust.
func setupCapabilitiesRequest(r *http.Request, origin string, selection profile.Selection) bool {
	u, e := url.Parse(origin)
	if e != nil || !validOrigin(origin, selection) || !selection.Inventory() || r == nil || r.URL == nil || r.Method != http.MethodGet || r.Host != u.Host || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.URL.Path != windowssetup.CapabilitiesPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Scheme != "" && r.URL.Scheme != u.Scheme || r.URL.Host != "" && r.URL.Host != u.Host || r.RequestURI != "" && r.RequestURI != r.URL.Path {
		return false
	}
	if selection.HTTPTest() {
		if r.TLS != nil {
			return false
		}
	} else if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
		return false
	}
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	size := 0
	for k, vs := range r.Header {
		switch strings.ToLower(k) {
		case "accept", "user-agent", "connection":
		default:
			return false
		}
		for _, v := range vs {
			size += len(k) + len(v)
			if size > 2048 {
				return false
			}
		}
	}
	return true
}
func (s *state) writeSetupCapabilities(w http.ResponseWriter) {
	if s.closed || s.unavailable || s.ctx.Err() != nil {
		fail(w, 503)
		return
	}
	raw, e := json.Marshal(windowssetup.Expected(s.bootstrap.ManagerInstanceID, s.bootstrap.EnrollmentOrigin, s.bootstrap.AgentOrigin))
	if e != nil {
		fail(w, 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
