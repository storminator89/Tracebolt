// Package lanconfig loads explicit deployment profiles without starting listeners
// or creating credentials. Plain HTTP is a separate, acknowledged test profile.
package lanconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/operatorauth"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.lan-config.v1"
const TLS = "tls"
const HTTPTest = "http-test"

var ErrConfiguration = errors.New("LAN configuration or file protection is invalid")

type Config struct {
	SchemaVersion            string `json:"schemaVersion"`
	Profile                  string `json:"profile"`
	OperatorListen           string `json:"operatorListen"`
	AgentListen              string `json:"agentListen"`
	OperatorOrigin           string `json:"operatorOrigin"`
	AgentOrigin              string `json:"agentOrigin"`
	TLSCertificateFile       string `json:"tlsCertificateFile"`
	TLSPrivateKeyFile        string `json:"tlsPrivateKeyFile"`
	AgentClientCAFile        string `json:"agentClientCAFile"`
	OperatorAuthFile         string `json:"operatorAuthFile"`
	StateDirectory           string `json:"stateDirectory"`
	WebDirectory             string `json:"webDirectory"`
	InsecureHTTPAcknowledged bool   `json:"insecureHTTPAcknowledged"`
}
type Material struct {
	Config       Config
	Server       tls.Certificate `json:"-"`
	ClientCA     []byte
	PasswordHash string                  `json:"-"`
	Operators    []operatorauth.Operator `json:"-"`
}

func (Material) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (Material) String() string               { return "lanconfig.Material{secrets:redacted}" }
func (Material) GoString() string             { return "lanconfig.Material{secrets:redacted}" }

// StrictObject rejects duplicates, aliases, unknown members, trailing input and nested values.
func StrictObject(raw []byte, out any, keys ...string) error {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return ErrConfiguration
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, e := dec.Token()
	if e != nil || t != json.Delim('{') {
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for dec.More() {
		t, e = dec.Token()
		key, ok := t.(string)
		if e != nil || !ok || !allowed[key] || seen[key] {
			return ErrConfiguration
		}
		seen[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return ErrConfiguration
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrConfiguration
		}
		if len(value) > 0 && (value[0] == '{' || value[0] == '[') {
			return ErrConfiguration
		}
	}
	if _, e = dec.Token(); e != nil {
		return ErrConfiguration
	}
	if _, e = dec.Token(); e != io.EOF {
		return ErrConfiguration
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil {
		return ErrConfiguration
	}
	return nil
}
func canonicalOrigin(raw, scheme string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != scheme || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || raw != scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(raw, "\\%\r\n\t ") {
		return nil, ErrConfiguration
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return nil, ErrConfiguration
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 || strings.HasSuffix(host, ".") {
			return nil, ErrConfiguration
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return nil, ErrConfiguration
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return nil, ErrConfiguration
				}
			}
		}
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || scheme == "https" && p == "443" || scheme == "http" && p == "80" {
			return nil, ErrConfiguration
		}
	}
	return u, nil
}
func validListen(raw string) bool {
	h, p, e := net.SplitHostPort(raw)
	n, ne := strconv.Atoi(p)
	return e == nil && ne == nil && net.ParseIP(h) != nil && n > 0 && n <= 65535 && strconv.Itoa(n) == p
}
func (c *Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return ErrConfiguration
	}
	if c.Profile == "" {
		c.Profile = TLS
	}
	scheme := "https"
	if c.Profile == HTTPTest {
		scheme = "http"
		if !c.InsecureHTTPAcknowledged || c.TLSCertificateFile != "" || c.TLSPrivateKeyFile != "" {
			return ErrConfiguration
		}
	} else if c.Profile != TLS || c.InsecureHTTPAcknowledged || c.TLSCertificateFile == "" || c.TLSPrivateKeyFile == "" {
		return ErrConfiguration
	}
	if !validListen(c.OperatorListen) || !validListen(c.AgentListen) || c.OperatorListen == c.AgentListen || c.OperatorOrigin == c.AgentOrigin {
		return ErrConfiguration
	}
	if _, e := canonicalOrigin(c.OperatorOrigin, scheme); e != nil {
		return e
	}
	if _, e := canonicalOrigin(c.AgentOrigin, scheme); e != nil {
		return e
	}
	for _, p := range []string{c.AgentClientCAFile, c.OperatorAuthFile, c.StateDirectory, c.WebDirectory} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, '\ufffd') {
			return ErrConfiguration
		}
	}
	if c.Profile == TLS {
		for _, p := range []string{c.TLSCertificateFile, c.TLSPrivateKeyFile} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p {
				return ErrConfiguration
			}
		}
	}
	return nil
}
func Load(path string) (Material, error) {
	fail := func() (Material, error) { return Material{}, ErrConfiguration }
	raw, e := ReadProtected(path, false, 16384)
	if e != nil {
		return fail()
	}
	var c Config
	if StrictObject(raw, &c, "schemaVersion", "profile", "operatorListen", "agentListen", "operatorOrigin", "agentOrigin", "tlsCertificateFile", "tlsPrivateKeyFile", "agentClientCAFile", "operatorAuthFile", "stateDirectory", "webDirectory", "insecureHTTPAcknowledged") != nil || c.Validate() != nil {
		return fail()
	}
	auth, e := ReadProtected(c.OperatorAuthFile, true, 32768)
	if e != nil {
		return fail()
	}
	defer clear(auth)
	passwordHash, operators, e := loadOperatorAuth(auth, c.Profile)
	if e != nil {
		return fail()
	}
	ca, e := ReadProtected(c.AgentClientCAFile, false, 65536)
	if e != nil {
		return fail()
	}
	m := Material{Config: c, ClientCA: ca, PasswordHash: passwordHash, Operators: operators}
	if c.Profile == TLS {
		cert, e := ReadProtected(c.TLSCertificateFile, false, 65536)
		if e != nil {
			return fail()
		}
		key, e := ReadProtected(c.TLSPrivateKeyFile, true, 32768)
		if e != nil {
			return fail()
		}
		defer clear(key)
		m.Server, e = tls.X509KeyPair(cert, key)
		if e != nil || len(m.Server.Certificate) == 0 {
			return fail()
		}
		leaf, e := x509.ParseCertificate(m.Server.Certificate[0])
		if e != nil {
			return fail()
		}
		for _, origin := range []string{c.OperatorOrigin, c.AgentOrigin} {
			u, _ := url.Parse(origin)
			if leaf.VerifyHostname(u.Hostname()) != nil {
				return fail()
			}
		}
	}
	return m, nil
}
