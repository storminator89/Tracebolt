//go:build linux

package enrollmentconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func profileFixture(t *testing.T) (Config, lanconfig.Material, string, time.Time) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	ip, ik, _ := ed25519.GenerateKey(rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("rootfixture")}
	rd, err := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if err != nil {
		t.Fatal("root fixture")
	}
	root, _ = x509.ParseCertificate(rd)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuerfixture")}
	id, err := x509.CreateCertificate(rand.Reader, issuer, root, ip, rk)
	if err != nil {
		t.Fatal("issuer fixture")
	}
	hash := sha256.Sum256(id)
	c := Config{SchemaVersion: SchemaVersion, Profile: "http-test", InstanceID: "manager_" + strings.Repeat("1", 32), IssuerCertificateFile: filepath.Join(dir, "issuer.pem"), IssuerRootFile: filepath.Join(dir, "root.pem"), IssuerPrivateKeyFile: filepath.Join(dir, "issuer.key"), ExpectedIssuerFingerprint: hex.EncodeToString(hash[:])}
	idPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id})
	private, _ := x509.MarshalPKCS8PrivateKey(ik)
	for path, raw := range map[string][]byte{c.IssuerCertificateFile: idPEM, c.IssuerRootFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rd}), c.IssuerPrivateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	state := filepath.Join(dir, "state")
	if os.Mkdir(state, 0700) != nil {
		t.Fatal("state fixture")
	}
	lan := lanconfig.Material{Config: lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: "http-test", OperatorListen: "127.0.0.1:8443", AgentListen: "127.0.0.1:8444", OperatorOrigin: "http://127.0.0.1:8443", AgentOrigin: "http://127.0.0.1:8444", AgentClientCAFile: c.IssuerCertificateFile, OperatorAuthFile: filepath.Join(dir, "auth.json"), StateDirectory: state, WebDirectory: filepath.Join(dir, "web"), InsecureHTTPAcknowledged: true}, ClientCA: idPEM}
	return c, lan, filepath.Join(dir, "enrollment.json"), now
}
func TestOptionalCollectionProfileAndExactModeBinding(t *testing.T) {
	c, lan, path, now := profileFixture(t)
	load := func() (Material, error) {
		raw, _ := json.Marshal(c)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("config fixture")
		}
		return Load(path, lan, now)
	}
	basic, err := load()
	if err != nil || basic.StoreConfig().Binding.CollectionProfile != enrollmentcrypto.CollectionProfile {
		t.Fatal("basic default failed")
	}
	if basic.PrepareMode(lan.Config.StateDirectory, 0) != nil {
		t.Fatal("basic mode failed")
	}
	before, _ := os.ReadFile(filepath.Join(lan.Config.StateDirectory, ModeFile))
	c.CollectionProfile = enrollmentcrypto.CollectionProfile
	explicit, err := load()
	if err != nil || !bytes.Equal(explicit.marker(), basic.marker()) || explicit.PrepareMode(lan.Config.StateDirectory, 0) != nil {
		t.Fatal("explicit basic not normalized")
	}
	c.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
	operations, err := load()
	if err != nil || operations.StoreConfig().Binding.CollectionProfile != c.CollectionProfile {
		t.Fatal("operations profile not loaded")
	}
	if operations.PrepareMode(lan.Config.StateDirectory, 0) == nil {
		t.Fatal("basic mode silently replaced")
	}
	after, _ := os.ReadFile(filepath.Join(lan.Config.StateDirectory, ModeFile))
	if !bytes.Equal(before, after) {
		t.Fatal("mismatch changed marker")
	}
	next := filepath.Join(filepath.Dir(path), "operational-state")
	if os.Mkdir(next, 0700) != nil {
		t.Fatal("fresh state")
	}
	lan.Config.StateDirectory = next
	operations, err = load()
	if err != nil || operations.PrepareMode(next, 0) != nil {
		t.Fatal("fresh operations marker failed")
	}
	c.CollectionProfile = "basic-readonly-v1"
	other, err := load()
	if err != nil || other.PrepareMode(next, 0) == nil {
		t.Fatal("operational mode silently returned to basic")
	}

	c.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	packages, err := load()
	if err != nil || packages.PrepareMode(next, 0) == nil {
		t.Fatal("package profile adopted original operational marker")
	}
	retained, _ := os.ReadFile(filepath.Join(next, ModeFile))
	c.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
	original, err := load()
	if err != nil || original.PrepareMode(next, 0) != nil {
		t.Fatal("rejected package profile changed original marker")
	}
	unchanged, _ := os.ReadFile(filepath.Join(next, ModeFile))
	if !bytes.Equal(retained, unchanged) {
		t.Fatal("marker changed on rejected package upgrade")
	}
	packageDir := filepath.Join(filepath.Dir(path), "package-state")
	if os.Mkdir(packageDir, 0700) != nil {
		t.Fatal("package state fixture")
	}
	lan.Config.StateDirectory = packageDir
	c.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	packages, err = load()
	if err != nil || packages.PrepareMode(packageDir, 0) != nil {
		t.Fatal("fresh package profile rejected")
	}
	c.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
	old, err := load()
	if err != nil || old.PrepareMode(packageDir, 0) == nil {
		t.Fatal("old profile adopted package marker")
	}
	for _, invalid := range []string{"managed-operations-v99", "Managed-operations-v1", " managed-operations-v1"} {
		c.CollectionProfile = invalid
		if _, err := load(); err == nil {
			t.Fatal("unknown collection accepted")
		}
	}
}
