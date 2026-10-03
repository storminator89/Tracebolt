//go:build linux

package security_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
)

// These fixtures use generated ephemeral test keys and private temporary files.
// No listener, deployment, operating-system trust store, or live credential is used.
type enrollmentConfigFixture struct {
	dir, path string
	now       time.Time
	config    enrollmentconfig.Config
	lan       lanconfig.Material
	keyPEM    []byte
}

func enrollmentConfigWrite(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal("fixture write failed")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("fixture mode failed")
	}
}

func enrollmentConfigPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func enrollmentConfigKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral key generation failed")
	}
	return key
}

func enrollmentConfigCert(t *testing.T, template, parent *x509.Certificate, public any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal("ephemeral certificate generation failed")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("ephemeral certificate parse failed")
	}
	return cert
}

func newEnrollmentConfigFixture(t *testing.T, profile string) *enrollmentConfigFixture {
	t.Helper()
	f := &enrollmentConfigFixture{dir: t.TempDir(), now: time.Now().UTC().Truncate(time.Second)}
	f.path = filepath.Join(f.dir, "enrollment.json")
	rootKey, issuerKey := enrollmentConfigKey(t), enrollmentConfigKey(t)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral enrollment offline root"}, NotBefore: f.now.Add(-24 * time.Hour), NotAfter: f.now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root := enrollmentConfigCert(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral enrollment intermediate"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	issuer := enrollmentConfigCert(t, issuerTemplate, root, issuerKey.Public(), rootKey)
	digest := sha256.Sum256(issuer.Raw)
	f.config = enrollmentconfig.Config{SchemaVersion: enrollmentconfig.SchemaVersion, Profile: profile, InstanceID: enrollmentBoundaryID("manager_", 41), IssuerCertificateFile: filepath.Join(f.dir, "issuer.pem"), IssuerPrivateKeyFile: filepath.Join(f.dir, "issuer.key"), IssuerRootFile: filepath.Join(f.dir, "root.pem"), ExpectedIssuerFingerprint: hex.EncodeToString(digest[:])}
	privateDER, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		t.Fatal("ephemeral key encoding failed")
	}
	f.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	enrollmentConfigWrite(t, f.config.IssuerCertificateFile, enrollmentConfigPEM(issuer.Raw), 0644)
	enrollmentConfigWrite(t, f.config.IssuerRootFile, enrollmentConfigPEM(root.Raw), 0644)
	enrollmentConfigWrite(t, f.config.IssuerPrivateKeyFile, f.keyPEM, 0600)
	scheme := "https"
	if profile == lanconfig.HTTPTest {
		scheme = "http"
	}
	f.lan.Config = lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: profile, OperatorListen: "127.0.0.1:18443", AgentListen: "127.0.0.1:18444", OperatorOrigin: scheme + "://127.0.0.1:18443", AgentOrigin: scheme + "://[::1]:18444", AgentClientCAFile: f.config.IssuerCertificateFile, OperatorAuthFile: filepath.Join(f.dir, "auth.json"), StateDirectory: filepath.Join(f.dir, "state"), WebDirectory: filepath.Join(f.dir, "web"), InsecureHTTPAcknowledged: profile == lanconfig.HTTPTest}
	f.lan.ClientCA = enrollmentConfigPEM(issuer.Raw)
	for _, path := range []string{f.lan.Config.StateDirectory, f.lan.Config.WebDirectory} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal("fixture directory failed")
		}
	}
	if profile == lanconfig.TLS {
		f.lan.Config.TLSCertificateFile = filepath.Join(f.dir, "server.pem")
		f.lan.Config.TLSPrivateKeyFile = filepath.Join(f.dir, "server.key")
		f.config.BootstrapServerCAFile = filepath.Join(f.dir, "server-root.pem")
		f.setServer(t, nil, nil, nil)
	}
	f.save(t)
	return f
}

func (f *enrollmentConfigFixture) save(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal("fixture config encoding failed")
	}
	enrollmentConfigWrite(t, f.path, raw, 0644)
}

func (f *enrollmentConfigFixture) setServer(t *testing.T, rootKey crypto.Signer, rootEdit, leafEdit func(*x509.Certificate)) {
	t.Helper()
	if rootKey == nil {
		rootKey = enrollmentConfigKey(t)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Ephemeral server root"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if rootEdit != nil {
		rootEdit(rootTemplate)
	}
	root := enrollmentConfigCert(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	leafKey := enrollmentConfigKey(t)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "Ephemeral loopback TLS server"}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if leafEdit != nil {
		leafEdit(leafTemplate)
	}
	leaf := enrollmentConfigCert(t, leafTemplate, root, leafKey.Public(), rootKey)
	f.lan.Server = tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}
	enrollmentConfigWrite(t, f.config.BootstrapServerCAFile, enrollmentConfigPEM(root.Raw), 0644)
}

func (f *enrollmentConfigFixture) load(t *testing.T) enrollmentconfig.Material {
	t.Helper()
	material, err := enrollmentconfig.Load(f.path, f.lan, f.now)
	if err != nil {
		t.Fatal("valid enrollment configuration rejected", err)
	}
	return material
}

func TestIndependentEnrollmentConfigBindingAndRedaction(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, profile)
			m := f.load(t)
			binding := m.StoreConfig().Binding
			if binding.InstanceID != f.config.InstanceID || binding.Profile != profile || binding.Origin != f.lan.Config.OperatorOrigin || binding.CollectionProfile != enrollmentcrypto.CollectionProfile || binding.IssuerFingerprint != f.config.ExpectedIssuerFingerprint {
				t.Fatal("store binding changed")
			}
			if !m.ValidFor(f.lan.Config) || m.Issuer() == nil || m.RootPEM() == "" || m.IssuerPEM() == "" || (m.ServerCAPEM() == "") != (profile == lanconfig.HTTPTest) {
				t.Fatal("loaded handle contract changed")
			}
			for _, edit := range []func(*lanconfig.Config){func(c *lanconfig.Config) { c.OperatorOrigin += "0" }, func(c *lanconfig.Config) { c.AgentOrigin += "0" }, func(c *lanconfig.Config) { c.StateDirectory += "-other" }, func(c *lanconfig.Config) { c.Profile = "other" }} {
				c := f.lan.Config
				edit(&c)
				if m.ValidFor(c) {
					t.Fatal("material accepted a changed runtime binding")
				}
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			outputs := []string{string(raw)}
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
				outputs = append(outputs, fmt.Sprintf(format, m), fmt.Sprintf(format, &m))
			}
			block, _ := pem.Decode(f.keyPEM)
			for _, out := range outputs {
				if strings.Contains(out, "PRIVATE KEY") || bytes.Contains([]byte(out), block.Bytes) || !strings.Contains(strings.ToLower(out), "redact") {
					t.Fatal("enrollment material formatting was not redacted")
				}
			}
		})
	}
}

func TestIndependentEnrollmentConfigRejectsUnboundMaterial(t *testing.T) {
	for name, edit := range map[string]func(*enrollmentConfigFixture){
		"profile mismatch": func(f *enrollmentConfigFixture) { f.config.Profile = lanconfig.HTTPTest },
		"invalid instance": func(f *enrollmentConfigFixture) { f.config.InstanceID = "manager_ordinary-name" },
		"uppercase fingerprint": func(f *enrollmentConfigFixture) {
			f.config.ExpectedIssuerFingerprint = strings.ToUpper(f.config.ExpectedIssuerFingerprint)
		},
		"wrong fingerprint":           func(f *enrollmentConfigFixture) { f.config.ExpectedIssuerFingerprint = strings.Repeat("a", 64) },
		"relative private key":        func(f *enrollmentConfigFixture) { f.config.IssuerPrivateKeyFile = "issuer.key" },
		"root used as ingress issuer": func(f *enrollmentConfigFixture) { f.lan.ClientCA, _ = os.ReadFile(f.config.IssuerRootFile) },
		"extra ingress CA":            func(f *enrollmentConfigFixture) { f.lan.ClientCA = append(f.lan.ClientCA, f.lan.ClientCA...) },
		"server chain missing":        func(f *enrollmentConfigFixture) { f.lan.Server.Certificate = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, lanconfig.TLS)
			edit(f)
			f.save(t)
			if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
				t.Fatal("unbound material accepted", err)
			}
		})
	}
	f := newEnrollmentConfigFixture(t, lanconfig.HTTPTest)
	f.config.BootstrapServerCAFile = f.config.IssuerRootFile
	f.save(t)
	if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
		t.Fatal("HTTP test profile accepted TLS bootstrap trust")
	}
}

func TestIndependentEnrollmentConfigProtectedFiles(t *testing.T) {
	for name, change := range map[string]func(*testing.T, *enrollmentConfigFixture){
		"private key group readable": func(t *testing.T, f *enrollmentConfigFixture) {
			if os.Chmod(f.config.IssuerPrivateKeyFile, 0640) != nil {
				t.Fatal("chmod fixture")
			}
		},
		"public issuer writable": func(t *testing.T, f *enrollmentConfigFixture) {
			if os.Chmod(f.config.IssuerCertificateFile, 0664) != nil {
				t.Fatal("chmod fixture")
			}
		},
		"config writable": func(t *testing.T, f *enrollmentConfigFixture) {
			if os.Chmod(f.path, 0664) != nil {
				t.Fatal("chmod fixture")
			}
		},
		"private key symlink": func(t *testing.T, f *enrollmentConfigFixture) {
			path := filepath.Join(f.dir, "key-link")
			if os.Symlink(f.config.IssuerPrivateKeyFile, path) != nil {
				t.Fatal("symlink fixture")
			}
			f.config.IssuerPrivateKeyFile = path
			f.save(t)
		},
		"private key hard link": func(t *testing.T, f *enrollmentConfigFixture) {
			if os.Link(f.config.IssuerPrivateKeyFile, filepath.Join(f.dir, "key-copy")) != nil {
				t.Fatal("hard link fixture")
			}
		},
		"issuer PEM extra block": func(t *testing.T, f *enrollmentConfigFixture) {
			enrollmentConfigWrite(t, f.config.IssuerCertificateFile, append(bytes.Clone(f.lan.ClientCA), f.lan.ClientCA...), 0644)
		},
		"issuer PEM prefix": func(t *testing.T, f *enrollmentConfigFixture) {
			enrollmentConfigWrite(t, f.config.IssuerCertificateFile, append([]byte("not a certificate\n"), f.lan.ClientCA...), 0644)
		},
		"private PEM extra block": func(t *testing.T, f *enrollmentConfigFixture) {
			enrollmentConfigWrite(t, f.config.IssuerPrivateKeyFile, append(bytes.Clone(f.keyPEM), f.keyPEM...), 0600)
		},
		"duplicate JSON key": func(t *testing.T, f *enrollmentConfigFixture) {
			raw, _ := os.ReadFile(f.path)
			raw = append([]byte(`{"schemaVersion":"tracebolt.enrollment-config.v2",`), raw[1:]...)
			enrollmentConfigWrite(t, f.path, raw, 0644)
		},
		"unknown JSON key": func(t *testing.T, f *enrollmentConfigFixture) {
			raw, _ := os.ReadFile(f.path)
			raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			enrollmentConfigWrite(t, f.path, raw, 0644)
		},
		"oversized config": func(t *testing.T, f *enrollmentConfigFixture) {
			enrollmentConfigWrite(t, f.path, bytes.Repeat([]byte(" "), 16385), 0644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, lanconfig.TLS)
			change(t, f)
			if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
				t.Fatal("unprotected or ambiguous material accepted", err)
			}
		})
	}
}

func TestIndependentEnrollmentConfigBootstrapListenerTrust(t *testing.T) {
	for name, edits := range map[string][2]func(*x509.Certificate){
		"expired server root":            {func(c *x509.Certificate) { c.NotAfter = time.Now().UTC().Add(-time.Second) }, nil},
		"future server root":             {func(c *x509.Certificate) { c.NotBefore = time.Now().UTC().Add(time.Hour) }, nil},
		"root lacks certificate signing": {func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }, nil},
		"operator SAN missing":           {nil, func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("::1")} }},
		"agent SAN missing":              {nil, func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }},
		"server dual role":               {nil, func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) }},
		"expired server leaf":            {nil, func(c *x509.Certificate) { c.NotAfter = time.Now().UTC().Add(-time.Second) }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, lanconfig.TLS)
			f.setServer(t, nil, edits[0], edits[1])
			if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
				t.Fatal("bootstrap trust did not cover actual listener policy", err)
			}
		})
	}
	t.Run("unrelated root", func(t *testing.T) {
		f := newEnrollmentConfigFixture(t, lanconfig.TLS)
		other := newEnrollmentConfigFixture(t, lanconfig.TLS)
		raw, _ := os.ReadFile(other.config.BootstrapServerCAFile)
		enrollmentConfigWrite(t, f.config.BootstrapServerCAFile, raw, 0644)
		if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
			t.Fatal("unrelated bootstrap root accepted")
		}
	})
	t.Run("ordinary weak RSA root", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal("ephemeral RSA fixture")
		}
		f := newEnrollmentConfigFixture(t, lanconfig.TLS)
		f.setServer(t, key, nil, nil)
		if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
			t.Fatal("weak bootstrap server root accepted")
		}
	})
	t.Run("ordinary SHA1 root", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal("ephemeral RSA fixture")
		}
		f := newEnrollmentConfigFixture(t, lanconfig.TLS)
		f.setServer(t, key, func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA }, nil)
		if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); !errors.Is(err, enrollmentconfig.ErrConfiguration) {
			t.Fatal("SHA1 bootstrap server root accepted")
		}
	})
}

func TestIndependentEnrollmentConfigModeRejectsLegacyAndOrphans(t *testing.T) {
	for _, name := range []string{enrollmentconfig.ModeFile, enrollmentconfig.DatabaseFile, enrollmentconfig.DatabaseFile + "-wal", enrollmentconfig.DatabaseFile + "-shm", enrollmentconfig.DatabaseFile + "-journal"} {
		t.Run(name, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, lanconfig.TLS)
			m := f.load(t)
			path := filepath.Join(f.lan.Config.StateDirectory, name)
			raw := []byte("ephemeral interrupted-state sentinel")
			enrollmentConfigWrite(t, path, raw, 0600)
			if enrollmentconfig.RejectEnrollmentMode(f.lan.Config.StateDirectory) == nil {
				t.Fatal("default v1 mode accepted v2 residue")
			}
			if m.PrepareMode(f.lan.Config.StateDirectory, 0) == nil {
				t.Fatal("v2 adopted unmarked database or malformed marker")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(raw, after) {
				t.Fatal("failed preparation changed existing residue")
			}
			if name != enrollmentconfig.ModeFile {
				if _, err := os.Lstat(filepath.Join(f.lan.Config.StateDirectory, enrollmentconfig.ModeFile)); !os.IsNotExist(err) {
					t.Fatal("orphan database acquired a new mode marker")
				}
			}
		})
	}
	for _, count := range []int{1, 2, -1} {
		f := newEnrollmentConfigFixture(t, lanconfig.TLS)
		m := f.load(t)
		if m.PrepareMode(f.lan.Config.StateDirectory, count) == nil {
			t.Fatal("legacy record count accepted, including a tombstone count")
		}
		if _, err := os.Lstat(filepath.Join(f.lan.Config.StateDirectory, enrollmentconfig.ModeFile)); !os.IsNotExist(err) {
			t.Fatal("legacy rejection wrote mode marker")
		}
	}
}

func TestIndependentEnrollmentConfigModeExactRestartBinding(t *testing.T) {
	for name, edit := range map[string]func(*testing.T, *enrollmentConfigFixture){
		"instance": func(_ *testing.T, f *enrollmentConfigFixture) {
			f.config.InstanceID = enrollmentBoundaryID("manager_", 42)
		},
		"operator origin": func(_ *testing.T, f *enrollmentConfigFixture) {
			f.lan.Config.OperatorOrigin = "https://127.0.0.1:19443"
		},
		"agent origin": func(_ *testing.T, f *enrollmentConfigFixture) { f.lan.Config.AgentOrigin = "https://[::1]:19444" },
		"server trust": func(t *testing.T, f *enrollmentConfigFixture) { f.setServer(t, nil, nil, nil) },
		"profile": func(_ *testing.T, f *enrollmentConfigFixture) {
			f.config.Profile = lanconfig.HTTPTest
			f.config.BootstrapServerCAFile = ""
			f.lan.Config.Profile = lanconfig.HTTPTest
			f.lan.Config.OperatorOrigin = "http://127.0.0.1:18443"
			f.lan.Config.AgentOrigin = "http://[::1]:18444"
			f.lan.Config.TLSCertificateFile, f.lan.Config.TLSPrivateKeyFile = "", ""
			f.lan.Config.InsecureHTTPAcknowledged = true
		},
		"issuer identity": func(t *testing.T, f *enrollmentConfigFixture) {
			other := newEnrollmentConfigFixture(t, lanconfig.TLS)
			f.config.IssuerCertificateFile = other.config.IssuerCertificateFile
			f.config.IssuerPrivateKeyFile = other.config.IssuerPrivateKeyFile
			f.config.IssuerRootFile = other.config.IssuerRootFile
			f.config.ExpectedIssuerFingerprint = other.config.ExpectedIssuerFingerprint
			f.lan.ClientCA = other.lan.ClientCA
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, lanconfig.TLS)
			m := f.load(t)
			dir := f.lan.Config.StateDirectory
			if err := m.PrepareMode(dir, 0); err != nil {
				t.Fatal("mode initialization failed", err)
			}
			path := filepath.Join(dir, enrollmentconfig.ModeFile)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("mode marker is not private")
			}
			if m.PrepareMode(dir, 0) != nil {
				t.Fatal("exact mode restart rejected")
			}
			if enrollmentconfig.RejectEnrollmentMode(dir) == nil {
				t.Fatal("initialized v2 state fell back to v1")
			}
			edit(t, f)
			f.save(t)
			changed := f.load(t)
			if changed.PrepareMode(dir, 0) == nil {
				t.Fatal("changed identity/trust adopted existing mode")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("mismatched restart rewrote marker")
			}
		})
	}
}

func TestIndependentEnrollmentConfigModeConcurrentPreparation(t *testing.T) {
	f := newEnrollmentConfigFixture(t, lanconfig.TLS)
	m := f.load(t)
	results := make(chan error, 16)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range cap(results) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- m.PrepareMode(f.lan.Config.StateDirectory, 0)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, enrollmentconfig.ErrConfiguration) {
			t.Fatal("unexpected preparation error")
		}
	}
	if accepted == 0 {
		t.Fatal("no exclusive marker creator completed")
	}
	if m.PrepareMode(f.lan.Config.StateDirectory, 0) != nil {
		t.Fatal("concurrent preparation left a corrupt marker")
	}
	path := filepath.Join(f.lan.Config.StateDirectory, enrollmentconfig.ModeFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("mode marker missing")
	}
	enrollmentConfigWrite(t, path, before[:len(before)/2], 0600)
	if m.PrepareMode(f.lan.Config.StateDirectory, 0) == nil {
		t.Fatal("torn marker was accepted or repaired")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before[:len(before)/2]) {
		t.Fatal("failed preparation rewrote interrupted marker")
	}
}
