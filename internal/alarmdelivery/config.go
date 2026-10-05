package alarmdelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/lanconfig"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
)

const ConfigSchemaVersion = "tracebolt.alarm-delivery-config.v1"

// ErrConfiguration deliberately contains neither a destination nor a file path.
var ErrConfiguration = errors.New("alarm_delivery_configuration_invalid")

// Config is an immutable startup snapshot. Its endpoint may itself contain a
// provider secret, so both endpoint and bearer material stay out of diagnostics.
type Config struct {
	enabled  bool
	binding  Binding
	endpoint string
	bearer   string
}

func (c Config) Enabled() bool              { return c.enabled }
func (c Config) Binding() Binding           { return c.binding }
func (Config) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (Config) String() string               { return "alarmdelivery.Config{redacted}" }
func (Config) GoString() string             { return "alarmdelivery.Config{redacted}" }

type configFile struct {
	SchemaVersion              string `json:"schemaVersion"`
	Enabled                    *bool  `json:"enabled"`
	PayloadSharingAcknowledged bool   `json:"payloadSharingAcknowledged"`
	ManagerInstanceID          string `json:"managerInstanceId"`
	Profile                    string `json:"profile"`
	DestinationID              string `json:"destinationId"`
	Generation                 string `json:"generation"`
	Endpoint                   string `json:"endpoint"`
	BearerTokenFile            string `json:"bearerTokenFile"`
}

// Load reads only an explicitly supplied protected file. An omitted path is off
// without any filesystem access. A disabled file never reads bearer material.
// Files and their replaceable ancestors follow the existing LAN safe-file rules.
func Load(path, managerID, profile string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	raw, err := lanconfig.ReadProtected(path, true, 16384)
	if err != nil {
		return Config{}, ErrConfiguration
	}
	defer clear(raw)
	var f configFile
	if lanconfig.StrictObject(raw, &f, "schemaVersion", "enabled", "payloadSharingAcknowledged", "managerInstanceId", "profile", "destinationId", "generation", "endpoint", "bearerTokenFile") != nil || f.SchemaVersion != ConfigSchemaVersion || f.Enabled == nil {
		return Config{}, ErrConfiguration
	}
	if f.BearerTokenFile != "" && (!filepath.IsAbs(f.BearerTokenFile) || filepath.Clean(f.BearerTokenFile) != f.BearerTokenFile || f.BearerTokenFile == path || strings.ContainsAny(f.BearerTokenFile, "\x00\r\n\ufffd")) {
		return Config{}, ErrConfiguration
	}
	// A minimal disabled file is valid. Partially supplied destinations are not.
	if !*f.Enabled && f.ManagerInstanceID == "" && f.Profile == "" && f.DestinationID == "" && f.Generation == "" && f.Endpoint == "" && f.BearerTokenFile == "" {
		return Config{}, nil
	}
	if f.ManagerInstanceID != managerID || f.Profile != profile || (*f.Enabled && !f.PayloadSharingAcknowledged) {
		return Config{}, ErrConfiguration
	}
	if _, err := parseWebhookEndpoint(f.Endpoint); err != nil {
		return Config{}, ErrConfiguration
	}
	b := Binding{ManagerInstanceID: f.ManagerInstanceID, Profile: f.Profile, DestinationID: f.DestinationID, Generation: f.Generation}
	b.Fingerprint = destinationFingerprint(b, f.Endpoint)
	if !b.Valid() {
		return Config{}, ErrConfiguration
	}
	c := Config{enabled: *f.Enabled, binding: b, endpoint: f.Endpoint}
	if !c.enabled || f.BearerTokenFile == "" {
		return c, nil
	}
	token, err := lanconfig.ReadProtected(f.BearerTokenFile, true, 4098)
	if err != nil {
		return Config{}, ErrConfiguration
	}
	defer clear(token)
	// One conventional final line ending is allowed; spaces/multiple lines are not.
	secret := string(token)
	if strings.HasSuffix(secret, "\n") {
		secret = strings.TrimSuffix(strings.TrimSuffix(secret, "\n"), "\r")
	}
	if !validBearer(secret) {
		return Config{}, ErrConfiguration
	}
	c.bearer = secret
	return c, nil
}

func destinationFingerprint(b Binding, endpoint string) string {
	// Length-delimited JSON prevents ambiguous concatenation. Authentication
	// rotation changes no routing identity; the exact URL and all bindings do.
	raw, _ := json.Marshal([]string{ConfigSchemaVersion, b.ManagerInstanceID, b.Profile, b.DestinationID, b.Generation, endpoint})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validBearer(s string) bool {
	if len(s) == 0 || len(s) > 4096 {
		return false
	}
	padding := false
	for _, r := range s {
		if r == '=' {
			padding = true
			continue
		}
		if padding || !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/", r)) {
			return false
		}
	}
	return s[0] != '='
}

func parseWebhookEndpoint(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, ErrConfiguration
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e || r == '\\' || r == '#' {
			return nil, ErrConfiguration
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || raw != u.String() || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ":") || (u.Port() != "" && u.Port() != "443") {
		return nil, ErrConfiguration
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicWebhookAddress(ip) {
			return nil, ErrConfiguration
		}
	} else {
		if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") || !strings.Contains(host, ".") {
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
	return u, nil
}
