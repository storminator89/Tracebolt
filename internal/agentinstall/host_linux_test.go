//go:build linux

package agentinstall

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installerBootstrap(t *testing.T, profile string) []byte {
	t.Helper()
	now := time.Now()
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	ip, _, _ := ed25519.GenerateKey(rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable installer test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("root")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(rd)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable client issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuer")}
	id, e := x509.CreateCertificate(rand.Reader, it, root, ip, rk)
	if e != nil {
		t.Fatal(e)
	}
	public := func(d []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})) }
	origin := "https://127.0.0.1:8443"
	serverCA := public(rd)
	if profile == "http-test" {
		origin = "http://127.0.0.1:8083"
		serverCA = ""
	}
	raw, _ := json.Marshal(enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), InvitationID: "invite_" + strings.Repeat("2", 32), Profile: profile, EnrollmentOrigin: origin, AgentOrigin: strings.TrimSuffix(origin, "3") + "4", CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerRootPEM: public(rd), IssuerPEM: public(id), ServerCAPEM: serverCA})
	return raw
}
func installerHostFixture(t *testing.T) (Request, *LinuxBackend, *[]string) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	h := &linuxHost{root: root, owner: os.Geteuid(), systemd: func() bool { return true }}
	for _, p := range []string{"/opt", "/etc/systemd/system", "/var/lib", "/usr/bin", "/usr/sbin"} {
		if os.MkdirAll(h.path(p), 0755) != nil {
			t.Fatal("dirs")
		}
	}
	for _, p := range []string{systemctlPath, useraddPath, nologinPath} {
		if os.WriteFile(h.path(p), []byte("fixture only, never executed"), 0555) != nil {
			t.Fatal("command fixture")
		}
	}
	h.terminal = func() bool { return true }
	h.unit = func(context.Context) (unitStatus, error) {
		if _, e := os.Lstat(h.path(UnitPath)); os.IsNotExist(e) {
			return unitStatus{LoadState: "not-found", ActiveState: "inactive", Transient: "no", MainPID: "0"}, nil
		}
		return unitStatus{LoadState: "loaded", ActiveState: "inactive", FragmentPath: UnitPath, UnitFileState: "enabled", Transient: "no", Names: UnitName, MainPID: "0"}, nil
	}
	acct := accountRecord{UID: os.Geteuid(), GID: os.Getegid()}
	exists := false
	h.account = func() (accountRecord, bool, error) { return acct, exists, nil }
	events := []string{}
	h.run = func(ctx context.Context, path string, args []string, a *accountRecord, interactive bool) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := filepath.Base(path)
		events = append(events, name+":"+strings.Join(args, " "))
		if name == "useradd" {
			if a != nil || exists {
				t.Fatal("account creation contract")
			}
			exists = true
			return nil
		}
		if name == "enroll-agent" {
			if a == nil || a.UID != acct.UID || !interactive {
				t.Fatal("enrollment retained root")
			}
			if os.MkdirAll(h.path(EnrollmentDirectory), 0700) != nil {
				t.Fatal("state fixture")
			}
			return os.WriteFile(filepath.Join(h.path(EnrollmentDirectory), "identity-sentinel"), []byte("retained identity fixture"), 0600)
		}
		if name == "lan-agent" {
			if a == nil || interactive || len(args) != 3 || args[2] != "--validate-guided" {
				t.Fatal("validation contract")
			}
			_, e := os.Stat(filepath.Join(h.path(EnrollmentDirectory), "identity-sentinel"))
			return e
		}
		if name != "systemctl" || a != nil {
			t.Fatal("unexpected command")
		}
		return nil
	}
	inputs := t.TempDir()
	r := Request{Action: Install, Apply: true, AgentBinary: filepath.Join(inputs, "lan-agent"), EnrollBinary: filepath.Join(inputs, "enroll-agent"), SourceArchive: filepath.Join(inputs, "source.tar"), BootstrapFile: filepath.Join(inputs, "bootstrap.json")}
	for _, v := range []struct{ path, cmd string }{{r.AgentBinary, "lan-agent"}, {r.EnrollBinary, "enroll-agent"}} {
		c := exec.Command("go", "build", "-buildvcs=false", "-o", v.path, "../../cmd/"+v.cmd)
		if c.Run() != nil {
			t.Fatal("fixture build")
		}
	}
	os.WriteFile(r.SourceArchive, []byte("disposable source byte fixture"), 0600)
	os.WriteFile(r.BootstrapFile, installerBootstrap(t, "tls"), 0600)
	r.AgentSHA256 = artifactDigest(t, r.AgentBinary)
	r.EnrollSHA256 = artifactDigest(t, r.EnrollBinary)
	r.SourceSHA256 = artifactDigest(t, r.SourceArchive)
	r.BootstrapSHA256 = artifactDigest(t, r.BootstrapFile)
	return r, &LinuxBackend{h}, &events
}
func TestLinuxAdapterDisposableFilesystemLifecycle(t *testing.T) {
	r, b, events := installerHostFixture(t)
	r.Apply = false
	before, _ := os.ReadDir(b.host.path("/var/lib"))
	out, e := Execute(context.Background(), r, b)
	after, _ := os.ReadDir(b.host.path("/var/lib"))
	if e != nil || len(*events) != 0 || len(before) != len(after) || !out.Plan.DryRun {
		t.Fatal("dry-run effects", e)
	}
	r.Apply = true
	out, e = Execute(context.Background(), r, b)
	if e != nil || !out.Committed {
		t.Fatal("install", e, out.FailureStage)
	}
	marker := filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel")
	raw, _ := os.ReadFile(marker)
	if _, e = Execute(context.Background(), r, b); e == nil {
		t.Fatal("fresh install overwrote existing")
	}
	for _, action := range []Action{Upgrade, Restart, Uninstall} {
		r.Action = action
		out, e = Execute(context.Background(), r, b)
		if e != nil || !out.Committed {
			t.Fatal(action, e, out.FailureStage)
		}
		same, _ := os.ReadFile(marker)
		if string(raw) != string(same) {
			t.Fatal("identity changed")
		}
	}
	if _, e = os.Lstat(b.host.path(UnitPath)); !os.IsNotExist(e) {
		t.Fatal("unit retained")
	}
	if b.host.secureDirectory(b.host.path(controlDirectory), true) != nil {
		t.Fatal("control directory")
	}
}
func TestLinuxAdapterRefusesForeignControlAndFailedValidation(t *testing.T) {
	r, b, events := installerHostFixture(t)
	dir := b.host.path(controlDirectory)
	os.Mkdir(dir, 0700)
	sentinel := filepath.Join(dir, "foreign")
	os.WriteFile(sentinel, []byte("preserve"), 0600)
	if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != 0 {
		t.Fatal("foreign control adopted")
	}
	raw, _ := os.ReadFile(sentinel)
	if string(raw) != "preserve" {
		t.Fatal("foreign state changed")
	}
}

func TestLinuxAdapterRetainedResumeAndRepeatedUninstall(t *testing.T) {
	r, b, events := installerHostFixture(t)
	original := b.host.run
	fail := true
	b.host.run = func(ctx context.Context, p string, args []string, a *accountRecord, interactive bool) error {
		if filepath.Base(p) == "enroll-agent" && fail {
			if e := original(ctx, p, args, a, interactive); e != nil {
				return e
			}
			return ErrOperation
		}
		return original(ctx, p, args, a, interactive)
	}
	out, e := Execute(context.Background(), r, b)
	if e == nil || !out.RolledBack {
		t.Fatal("expected safe retained rollback", e)
	}
	marker := filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel")
	old, _ := os.ReadFile(marker)
	owner, e := b.host.readOwnership()
	if e != nil || owner.Status != "prepared" {
		t.Fatal("missing retained authority")
	}
	n := len(*events)
	if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != n {
		t.Fatal("resume consent bypassed")
	}
	r.Resume = true
	fail = false
	out, e = Execute(context.Background(), r, b)
	if e != nil || !out.Committed {
		t.Fatal("resume", e, out.FailureStage)
	}
	same, _ := os.ReadFile(marker)
	if string(same) != string(old) {
		t.Fatal("identity reset")
	}
	r.Resume = false
	r.Action = Uninstall
	if _, e = Execute(context.Background(), r, b); e != nil {
		t.Fatal("uninstall", e)
	}
	n = len(*events)
	if _, e = Execute(context.Background(), r, b); e != nil || len(*events) != n {
		t.Fatal("repeat uninstall performed a command", e)
	}
}
func TestLinuxAdapterRejectsTerminalAndForeignUnitBeforeMutation(t *testing.T) {
	r, b, events := installerHostFixture(t)
	b.host.terminal = func() bool { return false }
	if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != 0 {
		t.Fatal("missing terminal mutated")
	}
	b.host.terminal = func() bool { return true }
	for _, status := range []unitStatus{{LoadState: "loaded", FragmentPath: "/usr/lib/systemd/system/tracebolt-agent.service"}, {LoadState: "loaded", FragmentPath: UnitPath, DropInPaths: "/run/override"}, {LoadState: "loaded", Transient: "yes"}, {LoadState: "not-found", ActiveState: "active", MainPID: "123"}} {
		b.host.unit = func(context.Context) (unitStatus, error) { return status, nil }
		if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != 0 {
			t.Fatal("foreign unit mutated")
		}
	}
}
func TestLinuxAdapterUncertainUseraddRetainsEvidence(t *testing.T) {
	r, b, _ := installerHostFixture(t)
	original := b.host.run
	b.host.run = func(ctx context.Context, p string, args []string, a *accountRecord, interactive bool) error {
		e := original(ctx, p, args, a, interactive)
		if filepath.Base(p) == "useradd" {
			return ErrOperation
		}
		return e
	}
	result, e := Execute(context.Background(), r, b)
	if e == nil || result.RolledBack {
		t.Fatal("uncertain account creation claimed rolled back")
	}
	owner, e := b.host.readOwnership()
	if e != nil || owner.Status != "preparing" {
		t.Fatal("uncertain account ownership lost")
	}
	if _, e = os.Stat(filepath.Join(b.host.path(controlDirectory), "transaction.json")); e != nil {
		t.Fatal("uncertain journal lost")
	}
}
func TestAccountUnitAndCgroupPurePolicies(t *testing.T) {
	passwd := Account + ":x:1234:2345::" + StateDirectory + ":" + nologinPath + "\n"
	groups := Account + ":x:2345:\n"
	if a, ok, e := parseAccountFiles([]byte(passwd), []byte(groups)); e != nil || !ok || a.UID != 1234 {
		t.Fatal("valid account rejected")
	}
	for _, v := range []struct{ p, g string }{{"", groups}, {passwd + "alias:x:1234:4567::/:/bin/false\n", groups}, {passwd, groups + "alias:x:2345:\n"}, {passwd, groups + "extra:x:4567:" + Account + "\n"}, {strings.Replace(passwd, "1234", "4294967296", 1), groups}} {
		if _, _, e := parseAccountFiles([]byte(v.p), []byte(v.g)); e == nil {
			t.Fatal("identity collision accepted")
		}
	}
	for _, raw := range []string{"populated 1\nfrozen 0\n", "populated 0\npopulated 0\n", "frozen 0\n"} {
		if cgroupUnpopulated([]byte(raw)) {
			t.Fatal("undrained cgroup accepted")
		}
	}
	if !cgroupUnpopulated([]byte("populated 0\nfrozen 0\n")) {
		t.Fatal("empty hierarchical cgroup rejected")
	}
}

func TestLinuxAdapterRollbackRestoresEnablementAndPreservesIdentity(t *testing.T) {
	r, b, _ := installerHostFixture(t)
	if _, e := Execute(context.Background(), r, b); e != nil {
		t.Fatal("install", e)
	}
	for _, action := range []Action{Uninstall, Upgrade} {
		r.Action = action
		enabled := true
		original := b.host.run
		oldUnit := b.host.unit
		b.host.unit = func(ctx context.Context) (unitStatus, error) {
			s, e := oldUnit(ctx)
			if s.LoadState == "loaded" {
				s.UnitFileState = "disabled"
				if enabled {
					s.UnitFileState = "enabled"
				}
			}
			return s, e
		}
		failed := false
		b.host.run = func(ctx context.Context, p string, args []string, a *accountRecord, interactive bool) error {
			if filepath.Base(p) == "systemctl" && len(args) > 0 {
				if args[0] == "enable" {
					enabled = true
				}
				if args[0] == "disable" {
					enabled = false
				}
				want := "disable"
				if action == Upgrade {
					want = "enable"
				}
				if args[0] == want && !failed {
					failed = true
					return ErrOperation
				}
			}
			return original(ctx, p, args, a, interactive)
		}
		out, e := Execute(context.Background(), r, b)
		if e == nil || !out.RolledBack || !enabled {
			t.Fatal("enablement was not restored", action, e, out.FailureStage)
		}
		if _, e = os.Stat(filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel")); e != nil {
			t.Fatal("identity lost")
		}
		b.host.run = original
		b.host.unit = oldUnit
	}
}
func TestLinuxAdapterResumeRejectsRecreatedStateDomain(t *testing.T) {
	r, b, _ := installerHostFixture(t)
	original := b.host.run
	b.host.run = func(ctx context.Context, p string, args []string, a *accountRecord, interactive bool) error {
		if filepath.Base(p) == "enroll-agent" {
			return ErrOperation
		}
		return original(ctx, p, args, a, interactive)
	}
	out, e := Execute(context.Background(), r, b)
	if e == nil || !out.RolledBack {
		t.Fatal("prepare fixture")
	}
	state := b.host.path(StateDirectory)
	if os.Rename(state, state+"-preserved") != nil || os.Mkdir(state, 0700) != nil {
		t.Fatal("replace fixture")
	}
	r.Resume = true
	if _, e = Execute(context.Background(), r, b); e == nil {
		t.Fatal("replacement state adopted")
	}
	entries, _ := os.ReadDir(state)
	if len(entries) != 0 {
		t.Fatal("rejected replacement changed")
	}
}

func TestLinuxAdapterRejectsAlteredOwnedArtifacts(t *testing.T) {
	r, b, events := installerHostFixture(t)
	if _, e := Execute(context.Background(), r, b); e != nil {
		t.Fatal("install", e)
	}
	r.Action = Restart
	path := b.host.path(AgentPath)
	backup := path + ".preserved"
	if os.Rename(path, backup) != nil {
		t.Fatal("fixture preserve")
	}
	if os.Symlink(backup, path) != nil {
		t.Fatal("fixture symlink")
	}
	n := len(*events)
	if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != n {
		t.Fatal("owned symlink executed")
	}
	os.Remove(path)
	if os.Link(backup, path) != nil {
		t.Fatal("fixture hardlink")
	}
	if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != n {
		t.Fatal("owned hardlink executed")
	}
	os.Remove(path)
	if os.Rename(backup, path) != nil || os.Chmod(path, 0777) != nil {
		t.Fatal("fixture mode")
	}
	if _, e := Execute(context.Background(), r, b); e == nil || len(*events) != n {
		t.Fatal("permissive artifact executed")
	}
}
