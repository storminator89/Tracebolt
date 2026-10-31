//go:build linux

package managersetup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/lanconfig"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	c                   lanconfig.Config
	options             Options
	now                 time.Time
	config, output, dir string
}

func write(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}
func certificate(t *testing.T, template, parent *x509.Certificate, public, private any) []byte {
	t.Helper()
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func makeFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerPublic, issuerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	serverPublic, serverPrivate, _ := ed25519.GenerateKey(rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic offline root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(100 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rootDER := certificate(t, root, root, rootPublic, rootPrivate)
	root, _ = x509.ParseCertificate(rootDER)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic client issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(45 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	issuerDER := certificate(t, issuer, root, issuerPublic, rootPrivate)
	server := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Synthetic server"}, DNSNames: []string{"manager.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER := certificate(t, server, root, serverPublic, rootPrivate)
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.TLS, OperatorListen: "127.0.0.1:59337", AgentListen: "127.0.0.1:59338", OperatorOrigin: "https://manager.invalid:59337", AgentOrigin: "https://manager.invalid:59338", TLSCertificateFile: filepath.Join(dir, "server.pem"), TLSPrivateKeyFile: filepath.Join(dir, "server.key"), AgentClientCAFile: filepath.Join(dir, "issuer.pem"), OperatorAuthFile: filepath.Join(dir, "auth.json"), StateDirectory: filepath.Join(dir, "state"), WebDirectory: filepath.Join(dir, "web"), WindowsInventoryEnabled: true}
	for _, path := range []string{c.StateDirectory, c.WebDirectory} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, der := range map[string][]byte{c.TLSCertificateFile: serverDER, c.AgentClientCAFile: issuerDER, filepath.Join(dir, "root.pem"): rootDER} {
		write(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	}
	for path, key := range map[string]ed25519.PrivateKey{c.TLSPrivateKeyFile: serverPrivate, filepath.Join(dir, "issuer.key"): issuerPrivate} {
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		write(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	}
	hash := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)) + "$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	auth, _ := json.Marshal(map[string]string{"schemaVersion": "tracebolt.operator-auth.v1", "profile": "tls", "passwordHash": hash})
	write(t, c.OperatorAuthFile, auth, 0600)
	write(t, filepath.Join(c.WebDirectory, "index.html"), []byte("<!doctype html><title>synthetic fixture</title>"), 0600)
	fingerprint := sha256.Sum256(issuerDER)
	e := enrollmentconfig.Config{SchemaVersion: enrollmentconfig.SchemaVersion, Profile: "tls", InstanceID: "manager_" + strings.Repeat("1", 32), IssuerCertificateFile: c.AgentClientCAFile, IssuerPrivateKeyFile: filepath.Join(dir, "issuer.key"), IssuerRootFile: filepath.Join(dir, "root.pem"), ExpectedIssuerFingerprint: hex.EncodeToString(fingerprint[:]), BootstrapServerCAFile: filepath.Join(dir, "root.pem")}
	raw, _ := json.Marshal(e)
	enrollment := filepath.Join(dir, "enrollment.json")
	write(t, enrollment, raw, 0600)
	config := filepath.Join(dir, "source.json")
	raw, _ = json.Marshal(c)
	write(t, config, raw, 0600)
	return fixture{c, Options{ExpectedUID: os.Geteuid(), EnrollmentConfig: enrollment, RequireWindows: true}, now, config, filepath.Join(dir, "created.json"), dir}
}
func noListeners() ([]listener, error) { return nil, nil }
func inspectFixture(f fixture) Report {
	r := NewReport("doctor")
	inspect(&r, f.c, f.options, f.now, noListeners)
	return r
}
func hasCheck(r Report, code, status string) bool {
	for _, c := range r.Checks {
		if c.Code == code && c.Status == status {
			return true
		}
	}
	return false
}
func describe(r Report) string { raw, _ := json.Marshal(r); return string(raw) }

type fileSnapshot struct {
	Raw      string
	Mode     os.FileMode
	Size     int64
	Modified int64
}

func snapshot(t *testing.T, dir string) map[string]fileSnapshot {
	t.Helper()
	out := map[string]fileSnapshot{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := fileSnapshot{Mode: info.Mode(), Size: info.Size(), Modified: info.ModTime().UnixNano()}
		if !d.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry.Raw = string(raw)
		}
		relative, _ := filepath.Rel(dir, path)
		out[relative] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func assertRetained(t *testing.T, before, after map[string]fileSnapshot, except ...string) {
	t.Helper()
	skip := map[string]bool{".": true}
	for _, name := range except {
		skip[name] = true
	}
	for path, expected := range before {
		if !skip[path] && !reflect.DeepEqual(expected, after[path]) {
			t.Fatalf("existing path changed: %s", path)
		}
	}
}

func TestDoctorReadsWithoutCreatingStateOrChangingMaterial(t *testing.T) {
	f := makeFixture(t)
	// Intentionally not a SQLite DB: opening or recovering it would fail or mutate
	// the retained fixture. Doctor must not mistake config checks for DB health.
	write(t, filepath.Join(f.c.StateDirectory, "agents.db"), []byte("retained-not-opened-database"), 0600)
	write(t, filepath.Join(f.c.StateDirectory, "identity-mode-v2.json"), []byte("retained-not-adopted-marker"), 0600)
	before := snapshot(t, f.dir)
	r := inspectFixture(f)
	if !r.OK || !hasCheck(r, "issuer_trust_validity", "pass") || !hasCheck(r, "windows_profile", "pass") {
		t.Fatal(describe(r))
	}
	after := snapshot(t, f.dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("doctor mutated content, modes, modification times or directory entries")
	}
	if len(r.Limitations) == 0 || !strings.Contains(strings.Join(r.Limitations, " "), "Database contents") {
		t.Fatal("doctor overclaims DB/runtime readiness")
	}
}

func TestDoctorEntryPointUsesProtectedParserAndRedactsInputs(t *testing.T) {
	f := makeFixture(t)
	before := snapshot(t, f.dir)
	r := Doctor(f.config, f.options, f.now)
	if !hasCheck(r, "operator_auth", "pass") || !hasCheck(r, "issuer_trust_validity", "pass") {
		t.Fatal(describe(r))
	}
	if !reflect.DeepEqual(before, snapshot(t, f.dir)) {
		t.Fatal("entry point changed files")
	}
	marker := "private-marker-do-not-echo"
	for _, raw := range []string{`{"operatorOrigin":"` + marker + `"}`, `{"profile":"tls","profile":"tls"}`} {
		write(t, f.config, []byte(raw), 0600)
		r = Doctor(f.config, f.options, f.now)
		if r.OK || !hasCheck(r, "lan_config", "fail") || strings.Contains(describe(r), marker) || strings.Contains(describe(r), f.dir) {
			t.Fatal("unredacted or accepted invalid config")
		}
	}
	f.options.ExpectedUID = os.Geteuid() + 1
	r = Doctor("/missing/"+marker, f.options, f.now)
	if len(r.Checks) != 1 || !hasCheck(r, "runtime_uid", "fail") || strings.Contains(describe(r), marker) {
		t.Fatal("wrong UID not stopped before input")
	}
}

func TestTargetedDiagnostics(t *testing.T) {
	tests := []struct {
		name, code string
		mutate     func(*testing.T, *fixture)
	}{
		{"SAN", "operator_san", func(t *testing.T, f *fixture) { f.c.OperatorOrigin = "https://wrong.invalid:59337" }},
		{"origin", "tls_origins", func(t *testing.T, f *fixture) { f.c.AgentOrigin = "https://manager.invalid:59338/" }},
		{"key_mode", "server_key_file", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.c.TLSPrivateKeyFile, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"auth_mode", "operator_auth_file", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.c.OperatorAuthFile, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"auth_verifier", "operator_auth", func(t *testing.T, f *fixture) {
			write(t, f.c.OperatorAuthFile, []byte(`{"schemaVersion":"tracebolt.operator-auth.v1","profile":"tls","passwordHash":"private-verifier-marker"}`), 0600)
		}},
		{"issuer_missing", "issuer_missing", func(t *testing.T, f *fixture) { f.options.EnrollmentConfig = "" }},
		{"issuer_path_missing", "issuer_config_file", func(t *testing.T, f *fixture) { f.options.EnrollmentConfig = filepath.Join(f.dir, "missing.json") }},
		{"issuer_expired", "issuer_validity", func(t *testing.T, f *fixture) { f.now = f.now.Add(50 * 24 * time.Hour) }},
		{"issuer_key_mode", "issuer_trust_validity", func(t *testing.T, f *fixture) {
			if err := os.Chmod(filepath.Join(f.dir, "issuer.key"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"windows_not_enabled", "windows_profile", func(t *testing.T, f *fixture) { f.c.WindowsInventoryEnabled = false }},
		{"state_mode", "state_directory", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.c.StateDirectory, 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"frontend_missing", "frontend_index", func(t *testing.T, f *fixture) {
			if err := os.Remove(filepath.Join(f.c.WebDirectory, "index.html")); err != nil {
				t.Fatal(err)
			}
		}},
		{"server_expired", "server_validity", func(t *testing.T, f *fixture) { f.now = f.now.Add(95 * 24 * time.Hour) }},
		{"key_mismatch", "server_key_pair", func(t *testing.T, f *fixture) {
			raw, _ := os.ReadFile(filepath.Join(f.dir, "issuer.key"))
			write(t, f.c.TLSPrivateKeyFile, raw, 0600)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := makeFixture(t)
			test.mutate(t, &f)
			before := snapshot(t, f.dir)
			r := inspectFixture(f)
			if r.OK || !hasCheck(r, test.code, "fail") {
				t.Fatal(describe(r))
			}
			if !reflect.DeepEqual(before, snapshot(t, f.dir)) {
				t.Fatal("diagnosis changed files")
			}
			out := describe(r)
			if strings.Contains(out, f.dir) || strings.Contains(out, "private-verifier-marker") || strings.Contains(out, "$argon2id$") || strings.Contains(out, "PRIVATE KEY") {
				t.Fatal("private diagnostics escaped")
			}
			for _, check := range r.Checks {
				if check.Status == "fail" && check.NextStep == "" {
					t.Fatal("failure without concrete next step")
				}
			}
		})
	}
}

func TestCreateOnlyInitializationPreservesEveryExistingFile(t *testing.T) {
	f := makeFixture(t)
	before := snapshot(t, f.dir)
	r := initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
	if !r.OK || !r.Created {
		t.Fatal(describe(r))
	}
	raw, err := os.ReadFile(f.output)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := lanconfig.Parse(raw)
	if err != nil || parsed != f.c {
		t.Fatal("created config differs from reviewed config")
	}
	info, _ := os.Stat(f.output)
	if info.Mode().Perm() != 0600 {
		t.Fatal("configuration not private")
	}
	after := snapshot(t, f.dir)
	if len(after) != len(before)+1 {
		t.Fatal("init created more than one config file")
	}
	assertRetained(t, before, after)
	state, _ := os.ReadDir(f.c.StateDirectory)
	if len(state) != 0 {
		t.Fatal("init initialized state")
	}
	r = initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
	if r.OK || r.Created || !hasCheck(r, "output_exists", "fail") {
		t.Fatal(describe(r))
	}
	if !reflect.DeepEqual(after, snapshot(t, f.dir)) {
		t.Fatal("repeat init rewrote existing state")
	}
}

func TestInitializationRejectsRetainedStateAndUnprotectedDestinations(t *testing.T) {
	t.Run("nonempty", func(t *testing.T) {
		f := makeFixture(t)
		write(t, filepath.Join(f.c.StateDirectory, "retained"), []byte("floor"), 0600)
		before := snapshot(t, f.dir)
		r := initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
		if r.OK || !hasCheck(r, "fresh_state", "fail") {
			t.Fatal(describe(r))
		}
		if !reflect.DeepEqual(before, snapshot(t, f.dir)) {
			t.Fatal("retained state changed")
		}
	})
	t.Run("dangling_symlink", func(t *testing.T) {
		f := makeFixture(t)
		if err := os.Symlink(filepath.Join(f.dir, "absent"), f.output); err != nil {
			t.Fatal(err)
		}
		r := initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
		if r.OK || !hasCheck(r, "output_exists", "fail") {
			t.Fatal(describe(r))
		}
		if _, err := os.Stat(filepath.Join(f.dir, "absent")); !os.IsNotExist(err) {
			t.Fatal("symlink followed")
		}
	})
	t.Run("shared_parent", func(t *testing.T) {
		f := makeFixture(t)
		if err := os.Chmod(f.dir, 0755); err != nil {
			t.Fatal(err)
		}
		r := initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
		if r.OK || !hasCheck(r, "output_directory", "fail") {
			t.Fatal(describe(r))
		}
	})
	t.Run("bad_material", func(t *testing.T) {
		f := makeFixture(t)
		f.c.OperatorOrigin = "https://wrong.invalid:59337"
		r := initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
		if r.OK {
			t.Fatal("invalid material initialized")
		}
		if _, err := os.Lstat(f.output); !os.IsNotExist(err) {
			t.Fatal("created output before full validation")
		}
	})
}

func TestConcurrentInitializationCreatesExactlyOnce(t *testing.T) {
	f := makeFixture(t)
	var wg sync.WaitGroup
	results := make(chan Report, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
		}()
	}
	wg.Wait()
	close(results)
	created := 0
	for r := range results {
		if r.OK && r.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created %d times", created)
	}
	raw, err := os.ReadFile(f.output)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := lanconfig.Parse(raw); err != nil || c != f.c {
		t.Fatal("concurrent output invalid")
	}
}

func TestProtectedInputsRejectSymlinksAndHardlinks(t *testing.T) {
	for _, kind := range []string{"symbolic", "hard"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t)
			link := filepath.Join(f.dir, "key-link")
			var err error
			if kind == "symbolic" {
				err = os.Symlink(f.c.TLSPrivateKeyFile, link)
			} else {
				err = os.Link(f.c.TLSPrivateKeyFile, link)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.c.TLSPrivateKeyFile = link
			r := inspectFixture(f)
			if r.OK || !hasCheck(r, "server_key_file", "fail") {
				t.Fatal(describe(r))
			}
		})
	}
}

func TestPortSnapshotConflictUnknownAndOverlap(t *testing.T) {
	f := makeFixture(t)
	for _, test := range []struct {
		name, code, status string
		fn                 func() ([]listener, error)
	}{
		{"conflict", "operator_port", "fail", func() ([]listener, error) { return []listener{{netip.MustParseAddrPort("0.0.0.0:59337")}}, nil }},
		{"dualstack", "agent_port", "fail", func() ([]listener, error) { return []listener{{netip.MustParseAddrPort("[::]:59338")}}, nil }},
		{"unavailable", "port_snapshot", "unknown", func() ([]listener, error) { return nil, fmt.Errorf("private-proc-error") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := NewReport("doctor")
			inspectPorts(&r, f.c, test.fn)
			if r.OK || !hasCheck(r, test.code, test.status) || strings.Contains(describe(r), "private-proc-error") {
				t.Fatal(describe(r))
			}
		})
	}
	f.c.AgentListen = "0.0.0.0:59337"
	r := NewReport("doctor")
	inspectPorts(&r, f.c, noListeners)
	if r.OK || !hasCheck(r, "listener_overlap", "fail") {
		t.Fatal(describe(r))
	}
}

func TestAdditionalCapabilityDomainsAreNotSilentlyAccepted(t *testing.T) {
	f := makeFixture(t)
	f.c.WindowsUpdateJobsConfigFile = filepath.Join(f.dir, "uninspected-update-config.json")
	r := inspectFixture(f)
	if r.OK || !hasCheck(r, "additional_capabilities", "unknown") {
		t.Fatal(describe(r))
	}
}

func TestInitializationNeverWritesIntoStateOrFrontend(t *testing.T) {
	for _, tree := range []string{"state", "web"} {
		t.Run(tree, func(t *testing.T) {
			f := makeFixture(t)
			f.output = filepath.Join(f.dir, tree, "lan.json")
			before := snapshot(t, f.dir)
			r := initializeWithListeners(f.c, f.output, f.options, f.now, noListeners)
			if r.OK || r.Created || !hasCheck(r, "output_separation", "fail") {
				t.Fatal(describe(r))
			}
			if !reflect.DeepEqual(before, snapshot(t, f.dir)) {
				t.Fatal("configuration inserted into protected state or frontend")
			}
		})
	}
}

func TestStateFrontendAndCredentialTreesMustBeSeparated(t *testing.T) {
	t.Run("overlap", func(t *testing.T) {
		f := makeFixture(t)
		f.c.StateDirectory = filepath.Join(f.c.WebDirectory, "state")
		r := inspectFixture(f)
		if r.OK || !hasCheck(r, "directory_separation", "fail") {
			t.Fatal(describe(r))
		}
	})
	t.Run("auth_under_web", func(t *testing.T) {
		f := makeFixture(t)
		target := filepath.Join(f.c.WebDirectory, "auth.json")
		if err := os.Rename(f.c.OperatorAuthFile, target); err != nil {
			t.Fatal(err)
		}
		f.c.OperatorAuthFile = target
		r := inspectFixture(f)
		if r.OK || !hasCheck(r, "material_exposure", "fail") {
			t.Fatal(describe(r))
		}
	})
	t.Run("nested_issuer_key_under_web", func(t *testing.T) {
		f := makeFixture(t)
		var e enrollmentconfig.Config
		raw, _ := os.ReadFile(f.options.EnrollmentConfig)
		if json.Unmarshal(raw, &e) != nil {
			t.Fatal("fixture")
		}
		target := filepath.Join(f.c.WebDirectory, "issuer.key")
		if err := os.Rename(e.IssuerPrivateKeyFile, target); err != nil {
			t.Fatal(err)
		}
		e.IssuerPrivateKeyFile = target
		raw, _ = json.Marshal(e)
		write(t, f.options.EnrollmentConfig, raw, 0600)
		before := snapshot(t, f.dir)
		r := inspectFixture(f)
		if r.OK || !hasCheck(r, "issuer_material_exposure", "fail") {
			t.Fatal(describe(r))
		}
		if !reflect.DeepEqual(before, snapshot(t, f.dir)) {
			t.Fatal("issuer exposure check changed files")
		}
	})
	t.Run("config_under_web", func(t *testing.T) {
		f := makeFixture(t)
		target := filepath.Join(f.c.WebDirectory, "lan.json")
		raw, _ := json.Marshal(f.c)
		write(t, target, raw, 0600)
		r := Doctor(target, f.options, f.now)
		if r.OK || !hasCheck(r, "configuration_exposure", "fail") {
			t.Fatal(describe(r))
		}
	})
}

func TestPathContainmentUsesComponentsNotStringPrefixes(t *testing.T) {
	if !within("/srv/state/lan.json", "/srv/state") || !within("/srv/state", "/srv/state") || within("/srv/state-backup/lan.json", "/srv/state") || within("/srv/state/../private/lan.json", "/srv/state") {
		t.Fatal("unsafe tree containment")
	}
}
