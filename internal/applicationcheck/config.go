// Package applicationcheck makes bounded, explicitly configured HTTP observations
// from the management server. It never establishes endpoint or application health.
package applicationcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanconfig"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ConfigSchemaVersion = "tracebolt.application-checks-config.v1"
const MaxTargets = 8
const MaxAddresses = 16
const CheckTimeout = 5 * time.Second
const MaxResponseBytes = 4096
const MaxHeaderBytes = 16384

var ErrConfiguration = errors.New("application_checks_configuration_invalid")

type target struct {
	ID                        string   `json:"id"`
	URL                       string   `json:"url"`
	AllowedAddresses          []string `json:"allowedAddresses"`
	AllowPrivateLAN           bool     `json:"allowPrivateLAN"`
	PlaintextHTTPAcknowledged bool     `json:"plaintextHTTPAcknowledged"`
}

// Config is an immutable startup snapshot. Configuration never comes from the API.
type Config struct {
	enabled                    bool
	managerID, origin, profile string
	interval                   time.Duration
	targets                    []target
}

func (c Config) Enabled() bool { return c.enabled }
func (c Config) Matches(managerID, origin, profile string) bool {
	return !c.enabled || c.managerID == managerID && c.origin == origin && c.profile == profile
}
func (Config) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (Config) String() string               { return "applicationcheck.Config{redacted}" }
func (Config) GoString() string             { return "applicationcheck.Config{redacted}" }

// object rejects nulls, duplicate keys and case aliases at each known object.
func object(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	keys := map[string]bool{}
	for _, k := range allowed {
		keys[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, ErrConfiguration
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		tok, e = d.Token()
		k, ok := tok.(string)
		if e != nil || !ok || !keys[k] || out[k] != nil {
			return nil, ErrConfiguration
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, ErrConfiguration
		}
		out[k] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, ErrConfiguration
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrConfiguration
	}
	return out, nil
}
func decode[T any](m map[string]json.RawMessage, key string, out *T) bool {
	raw, ok := m[key]
	return ok && json.Unmarshal(raw, out) == nil
}

// Load reads only an explicit protected file. No file, disabled configuration,
// validation, or construction performs DNS or other network work.
func Load(path, managerID, origin, profile string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	raw, e := lanconfig.ReadProtected(path, true, 32768)
	if e != nil {
		return Config{}, ErrConfiguration
	}
	defer clear(raw)
	f, e := object(raw, "schemaVersion", "enabled", "managerInstanceId", "operatorOrigin", "profile", "intervalSeconds", "checksFromManagerAcknowledged", "targets")
	var schema string
	var enabled bool
	if e != nil || !decode(f, "schemaVersion", &schema) || schema != ConfigSchemaVersion || !decode(f, "enabled", &enabled) {
		return Config{}, ErrConfiguration
	}
	if !enabled {
		if len(f) != 2 {
			return Config{}, ErrConfiguration
		}
		return Config{}, nil
	}
	var id, o, p string
	var interval int
	var acknowledged bool
	var targets []json.RawMessage
	if !decode(f, "managerInstanceId", &id) || !decode(f, "operatorOrigin", &o) || !decode(f, "profile", &p) || !decode(f, "intervalSeconds", &interval) || !decode(f, "checksFromManagerAcknowledged", &acknowledged) || !decode(f, "targets", &targets) || !acknowledged || interval < 60 || interval > 3600 || len(targets) == 0 || len(targets) > MaxTargets || id != managerID || o != origin || p != profile || (p != lanconfig.TLS && p != lanconfig.HTTPTest) || o == "" {
		return Config{}, ErrConfiguration
	}
	c := Config{enabled: true, managerID: id, origin: o, profile: p, interval: time.Duration(interval) * time.Second}
	seen := map[string]bool{}
	for _, rawTarget := range targets {
		f, e := object(rawTarget, "id", "url", "allowedAddresses", "allowPrivateLAN", "plaintextHTTPAcknowledged")
		var t target
		if e != nil || !decode(f, "id", &t.ID) || !decode(f, "url", &t.URL) || !decode(f, "allowedAddresses", &t.AllowedAddresses) || !decode(f, "allowPrivateLAN", &t.AllowPrivateLAN) || !decode(f, "plaintextHTTPAcknowledged", &t.PlaintextHTTPAcknowledged) || !validID(t.ID) || seen[t.ID] {
			return Config{}, ErrConfiguration
		}
		u, e := parseURL(t.URL, p, t.PlaintextHTTPAcknowledged)
		if e != nil || len(t.AllowedAddresses) == 0 || len(t.AllowedAddresses) > MaxAddresses {
			return Config{}, ErrConfiguration
		}
		addresses := map[netip.Addr]bool{}
		for _, rawIP := range t.AllowedAddresses {
			ip, e := netip.ParseAddr(rawIP)
			if e != nil || ip.String() != rawIP || ip.Is4In6() || !allowedAddress(ip, t.AllowPrivateLAN) || addresses[ip] {
				return Config{}, ErrConfiguration
			}
			addresses[ip] = true
		}
		if literal, e := netip.ParseAddr(u.Hostname()); e == nil && !addresses[literal] {
			return Config{}, ErrConfiguration
		}
		seen[t.ID] = true
		c.targets = append(c.targets, t)
	}
	return c, nil
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 48 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func parseURL(raw, _ string, httpAcknowledged bool) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return nil, ErrConfiguration
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e || strings.ContainsRune("\\%?#", r) {
			return nil, ErrConfiguration
		}
	}
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || raw != u.String() || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ":") {
		return nil, ErrConfiguration
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && httpAcknowledged) || u.Scheme == "https" && httpAcknowledged {
		return nil, ErrConfiguration
	}
	host := u.Hostname()
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" || ip.Is4In6() || ip.String() != host {
			return nil, ErrConfiguration
		}
	} else {
		if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
			return nil, ErrConfiguration
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, ErrConfiguration
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return nil, ErrConfiguration
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, ErrConfiguration
		}
	}
	if strings.Contains(u.Path, "//") {
		return nil, ErrConfiguration
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, ErrConfiguration
		}
	}
	return u, nil
}

// Conservative special-purpose exclusions. Private opt-in admits only RFC1918
// and ULA, never loopback, link-local, translation ranges or metadata services.
var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"), netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("168.63.129.16/32"), netip.MustParsePrefix("fd00:ec2::254/128"), netip.MustParsePrefix("fd20:ce::254/128"),
}
var globalV6 = netip.MustParsePrefix("2000::/3")

func allowedAddress(ip netip.Addr, private bool) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range excluded {
		if p.Contains(ip) {
			return false
		}
	}
	if ip.IsPrivate() {
		return private
	}
	return ip.Is4() || globalV6.Contains(ip)
}
