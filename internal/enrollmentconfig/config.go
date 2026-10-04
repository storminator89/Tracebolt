// Package enrollmentconfig loads an explicit, protected enrollment-v2 profile.
// It never generates a CA/key, writes credentials, or starts a listener.
package enrollmentconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lantrust"
	"net/url"
	"path/filepath"
	"time"
)

const SchemaVersion = "tracebolt.enrollment-config.v2"

var ErrConfiguration = errors.New("enrollment configuration or protected material is invalid")

type Config struct {
	CollectionProfile         string `json:"collectionProfile,omitempty"`
	SchemaVersion             string `json:"schemaVersion"`
	Profile                   string `json:"profile"`
	InstanceID                string `json:"instanceId"`
	IssuerCertificateFile     string `json:"issuerCertificateFile"`
	IssuerPrivateKeyFile      string `json:"issuerPrivateKeyFile"`
	IssuerRootFile            string `json:"issuerRootFile"`
	ExpectedIssuerFingerprint string `json:"expectedIssuerFingerprint"`
	BootstrapServerCAFile     string `json:"bootstrapServerCAFile"`
}
type Material struct{ value *loaded }
type loaded struct {
	config                          Config
	lan                             lanconfig.Config
	issuer                          *enrollmentissuer.Issuer
	serverCAPEM, issuerPEM, rootPEM []byte
}

func (Material) String() string                       { return "enrollmentconfig.Material{secrets:redacted}" }
func (Material) GoString() string                     { return "enrollmentconfig.Material{secrets:redacted}" }
func (m Material) Format(f fmt.State, _ rune)         { _, _ = io.WriteString(f, m.String()) }
func (Material) MarshalJSON() ([]byte, error)         { return []byte(`{"secretsRedacted":true}`), nil }
func (m Material) ValidFor(lan lanconfig.Config) bool { return m.value != nil && m.value.lan == lan }
func (m Material) Issuer() *enrollmentissuer.Issuer {
	if m.value == nil {
		return nil
	}
	return m.value.issuer
}
func (m Material) ServerCAPEM() string {
	if m.value == nil {
		return ""
	}
	return string(m.value.serverCAPEM)
}
func (m Material) IssuerPEM() string {
	if m.value == nil {
		return ""
	}
	return string(m.value.issuerPEM)
}
func (m Material) RootPEM() string {
	if m.value == nil {
		return ""
	}
	return string(m.value.rootPEM)
}
func (m Material) StoreConfig() enrollmentstate.Config {
	if m.value == nil {
		return enrollmentstate.Config{}
	}
	v := m.value
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: v.config.InstanceID, Profile: v.config.Profile, Origin: v.lan.OperatorOrigin, CollectionProfile: v.config.CollectionProfile, IssuerFingerprint: v.issuer.Fingerprint()})
	cfg.RecordLimit = enrollmentservice.MaxRecords
	cfg.InvitationLimit = enrollmentservice.MaxRecords
	cfg.PendingLimit = enrollmentservice.MaxRecords
	return cfg
}
func parseCertificate(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrConfiguration
	}
	if !bytes.Equal(bytes.Join(bytes.Fields(raw), nil), bytes.Join(bytes.Fields(pem.EncodeToMemory(block)), nil)) {
		return nil, ErrConfiguration
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, ErrConfiguration
	}
	return cert, nil
}
func Load(path string, lan lanconfig.Material, now time.Time) (Material, error) {
	fail := func() (Material, error) { return Material{}, ErrConfiguration }
	if lan.Config.Validate() != nil {
		return fail()
	}
	raw, e := lanconfig.ReadProtected(path, false, 16384)
	if e != nil {
		return fail()
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "schemaVersion", "profile", "instanceId", "issuerCertificateFile", "issuerPrivateKeyFile", "issuerRootFile", "expectedIssuerFingerprint", "bootstrapServerCAFile", "collectionProfile") != nil || c.SchemaVersion != SchemaVersion || c.Profile != lan.Config.Profile || !enrollmentcrypto.ValidID(c.InstanceID, "manager_") || !enrollmentcrypto.ValidHash(c.ExpectedIssuerFingerprint) {
		return fail()
	}
	if c.CollectionProfile == "" {
		c.CollectionProfile = enrollmentcrypto.CollectionProfile
	}
	if !enrollmentcrypto.ValidCollectionProfile(c.CollectionProfile) {
		return fail()
	}
	for _, p := range []string{c.IssuerCertificateFile, c.IssuerPrivateKeyFile, c.IssuerRootFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fail()
		}
	}
	if c.Profile == lanconfig.TLS {
		if !filepath.IsAbs(c.BootstrapServerCAFile) || filepath.Clean(c.BootstrapServerCAFile) != c.BootstrapServerCAFile {
			return fail()
		}
	} else if c.BootstrapServerCAFile != "" {
		return fail()
	}
	issuerPEM, e := lanconfig.ReadProtected(c.IssuerCertificateFile, false, 16384)
	if e != nil {
		return fail()
	}
	rootPEM, e := lanconfig.ReadProtected(c.IssuerRootFile, false, 16384)
	if e != nil {
		return fail()
	}
	issuer, e := parseCertificate(issuerPEM)
	if e != nil {
		return fail()
	}
	root, e := parseCertificate(rootPEM)
	if e != nil {
		return fail()
	}
	// The client ingress trusts this dedicated intermediate directly. It must not
	// inherit the offline root's other potential agent issuers or legacy roots.
	ingressIssuer, e := parseCertificate(lan.ClientCA)
	if e != nil || !bytes.Equal(ingressIssuer.Raw, issuer.Raw) {
		return fail()
	}
	privatePEM, e := lanconfig.ReadProtected(c.IssuerPrivateKeyFile, true, 32768)
	if e != nil {
		return fail()
	}
	defer clear(privatePEM)
	block, rest := pem.Decode(privatePEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return fail()
	}
	defer clear(block.Bytes)
	if !bytes.Equal(bytes.Join(bytes.Fields(privatePEM), nil), bytes.Join(bytes.Fields(pem.EncodeToMemory(block)), nil)) {
		return fail()
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return fail()
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fail()
	}
	defer clear(edKey)
	signer, e := enrollmentissuer.New(issuer.Raw, root.Raw, edKey, c.ExpectedIssuerFingerprint, now)
	if e != nil {
		return fail()
	}
	var serverPEM []byte
	if c.Profile == lanconfig.TLS {
		serverPEM, e = lanconfig.ReadProtected(c.BootstrapServerCAFile, false, 16384)
		if e != nil {
			return fail()
		}
		if _, e = parseCertificate(serverPEM); e != nil {
			return fail()
		}
		names := []string{}
		for _, origin := range []string{lan.Config.OperatorOrigin, lan.Config.AgentOrigin} {
			u, e := url.Parse(origin)
			if e != nil {
				return fail()
			}
			names = append(names, u.Hostname())
		}
		if lantrust.ValidateServerTrust(lan.Server, serverPEM, names, now) != nil {
			return fail()
		}
	}
	return Material{&loaded{config: c, lan: lan.Config, issuer: signer, serverCAPEM: bytes.Clone(serverPEM), issuerPEM: bytes.Clone(issuerPEM), rootPEM: bytes.Clone(rootPEM)}}, nil
}
func (m Material) marker() []byte {
	if m.value == nil {
		return nil
	}
	v := m.value
	server := sha256.Sum256(v.serverCAPEM)
	root := sha256.Sum256(v.issuer.RootDER())
	raw, _ := json.Marshal(struct{ SchemaVersion, Profile, InstanceID, OperatorOrigin, AgentOrigin, CollectionProfile, IssuerFingerprint, IssuerRootFingerprint, ServerTrustHash string }{"tracebolt.identity-mode.v2", v.config.Profile, v.config.InstanceID, v.lan.OperatorOrigin, v.lan.AgentOrigin, v.config.CollectionProfile, v.issuer.Fingerprint(), hex.EncodeToString(root[:]), hex.EncodeToString(server[:])})
	return raw
}
