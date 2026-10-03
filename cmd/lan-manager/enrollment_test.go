//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func guidedFixture(t *testing.T, profile string) (lanconfig.Material, enrollmentconfig.Material, string) {
	t.Helper()
	m, _, _, _ := fixture(t, profile)
	serverCA := bytes.Clone(m.ClientCA)
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	ip, ik, _ := ed25519.GenerateKey(rand.Reader)
	rh := sha256.Sum256(rp)
	ih := sha256.Sum256(ip)
	root := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "Ephemeral offline test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		t.Fatal("root fixture")
	}
	root, _ = x509.ParseCertificate(rd)
	ca := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "Ephemeral online client issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	der, e := x509.CreateCertificate(rand.Reader, ca, root, ip, rk)
	if e != nil {
		t.Fatal("issuer fixture")
	}
	fp := sha256.Sum256(der)
	dir := filepath.Dir(m.Config.AgentClientCAFile)
	cfg := enrollmentconfig.Config{SchemaVersion: enrollmentconfig.SchemaVersion, Profile: profile, InstanceID: "manager_" + strings.Repeat("1", 32), IssuerCertificateFile: filepath.Join(dir, "issuer.pem"), IssuerPrivateKeyFile: filepath.Join(dir, "issuer.key"), IssuerRootFile: filepath.Join(dir, "offline-root-public.pem"), ExpectedIssuerFingerprint: hex.EncodeToString(fp[:])}
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ik)
	files := map[string][]byte{cfg.IssuerCertificateFile: issuerPEM, cfg.IssuerPrivateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), cfg.IssuerRootFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rd}), m.Config.AgentClientCAFile: issuerPEM}
	if profile == lanconfig.TLS {
		cfg.BootstrapServerCAFile = filepath.Join(dir, "operator-server-ca.pem")
		files[cfg.BootstrapServerCAFile] = serverCA
	}
	configPath := filepath.Join(dir, "enrollment.json")
	files[configPath], _ = json.Marshal(cfg)
	for path, raw := range files {
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private fixture write")
		}
	}
	m.ClientCA = issuerPEM
	enrolled, e := enrollmentconfig.Load(configPath, m, now)
	if e != nil {
		t.Fatal("guided profile rejected", e)
	}
	return m, enrolled, configPath
}
func TestGuidedRuntimeModeIsolationAndRestart(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, enrolled, _ := guidedFixture(t, profile)
			p, e := prepareWithEnrollment(m, &enrolled)
			if e != nil {
				t.Fatal("guided startup", e)
			}
			p.close()
			marker, e := os.ReadFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile))
			if e != nil {
				t.Fatal("missing mode marker")
			}
			p, e = prepareWithEnrollment(m, &enrolled)
			if e != nil {
				t.Fatal("guided restart", e)
			}
			p.close()
			after, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile))
			if !bytes.Equal(marker, after) {
				t.Fatal("mode marker changed")
			}
			if p, e = prepare(m); e == nil {
				p.close()
				t.Fatal("guided state downgraded into manual mode")
			}
			changed := m
			changed.Config.AgentOrigin = strings.Replace(m.Config.AgentOrigin, "://", "://different.", 1)
			if p, e = prepareWithEnrollment(changed, &enrolled); e == nil {
				p.close()
				t.Fatal("changed origin accepted")
			}
		})
	}
}
func TestGuidedRuntimeRejectsLegacyTombstone(t *testing.T) {
	m, enrolled, _ := guidedFixture(t, lanconfig.HTTPTest)
	if e := lanstore.PrepareProfileDirectory(m.Config.StateDirectory, m.Config.Profile); e != nil {
		t.Fatal(e)
	}
	legacy, e := lanstore.Open(filepath.Join(m.Config.StateDirectory, "agents.db"))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	a := lantrust.Agent{ID: "agent_" + strings.Repeat("2", 32), Label: "ordinary retired test record", FingerprintSHA256: strings.Repeat("3", 64), ApprovedAt: now.Add(-time.Minute), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), RevokedAt: now}
	if e = legacy.Save(context.Background(), a); e != nil {
		t.Fatal("fixture tombstone", e)
	}
	legacy.Close()
	if p, e := prepareWithEnrollment(m, &enrolled); e == nil {
		p.close()
		t.Fatal("legacy tombstone adopted")
	}
	if _, e = os.Lstat(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile)); !os.IsNotExist(e) {
		t.Fatal("failed legacy check wrote mode marker")
	}
}
func TestGuidedRuntimeRejectsUnmarkedPartialState(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run(suffix, func(t *testing.T) {
			m, enrolled, _ := guidedFixture(t, lanconfig.HTTPTest)
			if e := lanstore.PrepareProfileDirectory(m.Config.StateDirectory, m.Config.Profile); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(m.Config.StateDirectory, enrollmentconfig.DatabaseFile+suffix)
			before := []byte("unadopted ordinary fixture bytes")
			if os.WriteFile(path, before, 0600) != nil {
				t.Fatal("fixture")
			}
			if p, e := prepareWithEnrollment(m, &enrolled); e == nil {
				p.close()
				t.Fatal("partial state adopted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, before) {
				t.Fatal("partial state modified")
			}
			if _, e := os.Lstat(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile)); !os.IsNotExist(e) {
				t.Fatal("partial state received new marker")
			}
		})
	}
}
func TestGuidedMaterialRedactionAndProtection(t *testing.T) {
	m, enrolled, path := guidedFixture(t, lanconfig.TLS)
	raw, _ := os.ReadFile(path)
	var cfg enrollmentconfig.Config
	json.Unmarshal(raw, &cfg)
	key, _ := os.ReadFile(cfg.IssuerPrivateKeyFile)
	for _, value := range []any{enrolled, &enrolled} {
		b, _ := json.Marshal(value)
		if bytes.Contains(b, key) {
			t.Fatal("material JSON exposed key")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), "PRIVATE KEY") {
				t.Fatal("material format exposed key")
			}
		}
	}
	if os.Chmod(cfg.IssuerPrivateKeyFile, 0644) != nil {
		t.Fatal("fixture mode")
	}
	if _, e := enrollmentconfig.Load(path, m, time.Now().UTC()); e == nil {
		t.Fatal("readable issuer key accepted")
	}
}
