// Package lanclient is a bounded read-only, foreground LAN telemetry sender.
// It accepts preprovided material and never enrolls, issues keys or installs.
package lanclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lantrust"
	"localrmm/internal/signedhttp"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const ConfigVersion = "tracebolt.lan-agent.v1"
const GuidedConfigVersion = "tracebolt.lan-agent.v2"
const OperationalConfigVersion = "tracebolt.lan-agent.v3"
const PackageConfigVersion = "tracebolt.lan-agent.v4"
const CompleteConfigVersion = "tracebolt.lan-agent.v5"
const FrameVersion = "tracebolt.agent-telemetry.v1"
const FrameOperationalVersion = "tracebolt.agent-telemetry.v2"
const FramePackagesVersion = "tracebolt.agent-telemetry.v3"
const MaxPackageObservationBytes = 16 << 10
const MaxFrameBytes = 72 * 1024

var ErrConfiguration = errors.New("agent configuration or protected material is invalid")
var ErrState = errors.New("agent state is unavailable or incompatible")
var ErrObservation = errors.New("bounded observation could not be prepared")
var ErrTransport = errors.New("telemetry delivery was not acknowledged; pending observation retained")
var ErrReceipt = errors.New("telemetry receipt was invalid; pending observation retained")

type Config struct {
	CollectionProfile        string `json:"collectionProfile,omitempty"`
	SchemaVersion            string `json:"schemaVersion"`
	Profile                  string `json:"profile"`
	ManagerOrigin            string `json:"managerOrigin"`
	AgentID                  string `json:"agentId"`
	CertificateFile          string `json:"certificateFile"`
	PrivateKeyFile           string `json:"privateKeyFile"`
	ServerCAFile             string `json:"serverCAFile"`
	StateDirectory           string `json:"stateDirectory"`
	InsecureHTTPAcknowledged bool   `json:"insecureHTTPAcknowledged"`
}

// Material is opaque loaded credential/trust state. A zero value is unusable.
type Material struct {
	config      Config
	configPath  string // protected origin for current activated-material rereads; never serialized
	certificate tls.Certificate
	tlsConfig   *tls.Config
	binding     string
	loaded      bool
}

func (m Material) Profile() string            { return m.config.Profile }
func (Material) String() string               { return "lanclient.Material{secrets:redacted}" }
func (Material) GoString() string             { return "lanclient.Material{secrets:redacted}" }
func (Material) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func canonicalOrigin(raw, scheme string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 512 || u.Scheme != scheme || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || raw != scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(raw, "\\%\r\n\t ") {
		return nil, ErrConfiguration
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return nil, ErrConfiguration
	}
	if ip := net.ParseIP(host); ip == nil {
		if len(host) > 253 {
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
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || scheme == "https" && p == "443" || scheme == "http" && p == "80" {
			return nil, ErrConfiguration
		}
		authority = net.JoinHostPort(host, p)
	}
	if authority != u.Host {
		return nil, ErrConfiguration
	}
	return u, nil
}
func (c *Config) Validate() error {
	if c.SchemaVersion != ConfigVersion && !c.guided() {
		return ErrConfiguration
	}
	if c.SchemaVersion == OperationalConfigVersion {
		if c.CollectionProfile != enrollmentcrypto.CollectionProfileOperational {
			return ErrConfiguration
		}
	} else if c.SchemaVersion == PackageConfigVersion {
		if c.CollectionProfile != enrollmentcrypto.CollectionProfilePackages {
			return ErrConfiguration
		}
	} else if c.SchemaVersion == CompleteConfigVersion {
		if c.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
			return ErrConfiguration
		}
	} else if c.CollectionProfile != "" {
		return ErrConfiguration
	}
	if c.Profile == "" {
		c.Profile = "tls"
	}
	scheme := "https"
	if c.Profile == "http-test" {
		scheme = "http"
		if !c.InsecureHTTPAcknowledged || c.ServerCAFile != "" {
			return ErrConfiguration
		}
	} else if c.Profile != "tls" || c.InsecureHTTPAcknowledged || c.ServerCAFile == "" {
		return ErrConfiguration
	}
	origin, e := canonicalOrigin(c.ManagerOrigin, scheme)
	if e != nil {
		return e
	}
	if ip, e := netip.ParseAddr(origin.Hostname()); e == nil && !vettedAddresses([]netip.Addr{ip}, c.Profile == "http-test") {
		return ErrConfiguration
	}
	if len(c.AgentID) != 38 || !strings.HasPrefix(c.AgentID, "agent_") {
		return ErrConfiguration
	}
	b, e := hex.DecodeString(c.AgentID[6:])
	if e != nil || hex.EncodeToString(b) != c.AgentID[6:] {
		return ErrConfiguration
	}
	for _, p := range []string{c.CertificateFile, c.PrivateKeyFile, c.StateDirectory} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, '\ufffd') {
			return ErrConfiguration
		}
	}
	if c.Profile == "tls" && (!filepath.IsAbs(c.ServerCAFile) || filepath.Clean(c.ServerCAFile) != c.ServerCAFile) {
		return ErrConfiguration
	}
	return nil
}
func Load(path string) (Material, error) {
	fail := func() (Material, error) { return Material{}, ErrConfiguration }
	raw, e := lanconfig.ReadProtected(path, false, 16384)
	if e != nil {
		return fail()
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile") != nil || c.Validate() != nil {
		return fail()
	}
	m, err := loadConfig(c)
	if err == nil {
		m.configPath = path
	}
	return m, err
}
func loadConfig(c Config) (Material, error) {
	fail := func() (Material, error) { return Material{}, ErrConfiguration }
	if c.Validate() != nil {
		return fail()
	}
	cert, e := lanconfig.ReadProtected(c.CertificateFile, false, 65536)
	if e != nil {
		return fail()
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, 32768)
	if e != nil {
		return fail()
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) == 0 {
		return fail()
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return fail()
	}
	m := Material{config: c, certificate: pair}
	origin, _ := url.Parse(c.ManagerOrigin)
	if c.Profile == "tls" {
		ca, e := lanconfig.ReadProtected(c.ServerCAFile, false, 65536)
		if e != nil {
			return fail()
		}
		m.tlsConfig, e = lantrust.ClientTLSConfig(pair, ca, origin.Hostname())
		if e != nil {
			return fail()
		}
	} else {
		now := time.Now().UTC()
		if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
			return fail()
		}
		if len(pair.Certificate) != 1 || base64.RawStdEncoding.EncodedLen(len(pair.Certificate[0])) > signedhttp.MaxCertificateHeaderBytes {
			return fail()
		}
		if _, ok := pair.PrivateKey.(ed25519.PrivateKey); !ok {
			return fail()
		}
		// The signing helper validates key/leaf agreement without network access; the exclusive current client role was checked above.
		if _, e := signedhttp.NewSignedRequest(context.Background(), c.ManagerOrigin, pair, 1, time.Now().UTC(), []byte(`{}`)); e != nil {
			return fail()
		}
	}
	binding := senderBinding(c, leaf)
	m.binding = hex.EncodeToString(binding[:])
	m.loaded = true
	return m, nil
}

// Config is public metadata; sensitive key/hash material never appears in JSON.
var _ json.Marshaler = Material{}

func (m Material) valid() bool {
	if !m.loaded || m.config.Validate() != nil || len(m.certificate.Certificate) == 0 {
		return false
	}
	leaf, e := x509.ParseCertificate(m.certificate.Certificate[0])
	if e != nil {
		return false
	}
	now := time.Now().UTC()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return false
	}
	sum := senderBinding(m.config, leaf)
	if m.binding != hex.EncodeToString(sum[:]) {
		return false
	}
	if m.config.Profile == "tls" {
		u, _ := url.Parse(m.config.ManagerOrigin)
		return m.tlsConfig != nil && m.tlsConfig.RootCAs != nil && !m.tlsConfig.InsecureSkipVerify && m.tlsConfig.MinVersion >= tls.VersionTLS13 && m.tlsConfig.ServerName == u.Hostname() && len(m.tlsConfig.Certificates) == 1
	}
	return m.tlsConfig == nil
}

func senderBinding(c Config, leaf *x509.Certificate) [32]byte {
	domain := "tracebolt.sender-binding.v1\n"
	if c.SchemaVersion == GuidedConfigVersion {
		domain = "tracebolt.sender-binding.v2\n"
	}
	if c.SchemaVersion == OperationalConfigVersion {
		domain = "tracebolt.sender-binding.v3\n" + c.CollectionProfile + "\n"
	}
	if c.SchemaVersion == PackageConfigVersion {
		domain = "tracebolt.sender-binding.v4\n" + c.CollectionProfile + "\n"
	}
	if c.SchemaVersion == CompleteConfigVersion {
		domain = "tracebolt.sender-binding.v5\n" + c.CollectionProfile + "\n"
	}
	return sha256.Sum256([]byte(domain + c.Profile + "\n" + c.ManagerOrigin + "\n" + lantrust.Fingerprint(leaf) + "\n" + c.AgentID))
}

func (c Config) guided() bool {
	return c.SchemaVersion == GuidedConfigVersion || c.managed()
}

func (c Config) managed() bool {
	return c.SchemaVersion == OperationalConfigVersion || c.SchemaVersion == PackageConfigVersion || c.complete()
}

func (c Config) complete() bool {
	return c.SchemaVersion == CompleteConfigVersion && c.CollectionProfile == enrollmentcrypto.CollectionProfileComplete
}
func inventoryStateDirectory(c Config) string { return filepath.Join(c.StateDirectory, "inventory") }
func systemStateDirectory(c Config) string    { return filepath.Join(c.StateDirectory, "system") }
func systemStateBinding(m Material) string {
	sum := sha256.Sum256([]byte("tracebolt.system-observation-state.v1\x00" + m.binding))
	return hex.EncodeToString(sum[:])
}
