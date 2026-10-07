//go:build linux

package packagehelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/actionpermit"
	"localrmm/internal/mutationfence"
	"localrmm/internal/nativeapt"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testID = "update_11111111111111111111111111111111"
const testNow int64 = 1700000000

// Every subprocess in these tests is fake. No APT, dpkg, systemd, native helper,
// host unit, privileged path, permission grant or root execution is performed.
type fakeFence struct {
	mu           sync.Mutex
	entries      []mutationfence.Entry
	failComplete bool
}

func (f *fakeFence) Acquire(_ context.Context, o mutationfence.Owner, n int64) (mutationfence.Entry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.entries {
		if x.Owner.Action == o.Action && x.Owner.JobID == o.JobID {
			if x.Owner != o {
				return x, false, ErrConflict
			}
			return x, false, nil
		}
		if x.CompletedAt == 0 {
			return x, false, mutationfence.ErrBusy
		}
	}
	x := mutationfence.Entry{Owner: o, AdmittedAt: n, Outcome: "unknown"}
	f.entries = append(f.entries, x)
	return x, true, nil
}
func (f *fakeFence) Complete(_ context.Context, o mutationfence.Owner, out string, n int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failComplete {
		return ErrUncertain
	}
	for i := range f.entries {
		if f.entries[i].Owner == o {
			f.entries[i].CompletedAt = n
			f.entries[i].Outcome = out
			return nil
		}
	}
	return ErrRejected
}
func (f *fakeFence) Status(_ context.Context, o mutationfence.Owner) (mutationfence.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.entries {
		if x.Owner == o {
			return x, nil
		}
	}
	return mutationfence.Entry{}, ErrRejected
}

type fakeCommands struct {
	specs []commandSpec
	fn    func(commandSpec) (commandResult, error)
}

func (f *fakeCommands) run(s commandSpec) (commandResult, error) {
	// Definition queries have their own direct tests below; ordinary fake launch
	// logs track requested starts and operation/query subprocesses.
	if strings.Contains(strings.Join(s.args, " "), "--property=FragmentPath") {
		return commandResult{exit: 0, stdout: []byte("FragmentPath=" + RunnerUnitPath + "\nDropInPaths=\nNeedDaemonReload=no\nSlice=system.slice\n")}, nil
	}
	f.specs = append(f.specs, s)
	if f.fn != nil {
		return f.fn(s)
	}
	if strings.Contains(strings.Join(s.args, " "), "--property=Job") {
		return commandResult{exit: 0, started: true, stdout: []byte("MainPID=0\nActiveState=inactive\nJob=\n")}, nil
	}
	return commandResult{exit: 0, started: true, stdout: []byte("inactive\n")}, nil
}

type fixture struct {
	t        *testing.T
	fs       protectedFS
	a        authority
	key      ed25519.PrivateKey
	f        *fakeFence
	c        *fakeCommands
	now      int64
	p        packagepermit.Permit
	raw      []byte
	prepared nativeapt.Prepared
	hook     []byte
}

func (f *fixture) write(p string, b []byte) {
	f.t.Helper()
	dst := filepath.Join(f.fs.root, p)
	if e := os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
		f.t.Fatal(e)
	}
	if e := os.WriteFile(dst, b, 0600); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) json(p string, v any) {
	b, e := json.Marshal(v)
	if e != nil {
		f.t.Fatal(e)
	}
	f.write(p, b)
}
func (f *fixture) mkdir(p string) {
	if e := os.MkdirAll(filepath.Join(f.fs.root, p), 0700); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) clock() time.Time         { return time.Unix(f.now, 0) }
func (f *fixture) load() (authority, error) { return f.a, nil }
func (f *fixture) broker() broker           { return broker{f.fs, f.f, f.c, f.clock, f.load} }
func (f *fixture) runner() runner {
	return runner{f.fs, f.f, f.c, f.clock, f.load, func() (int, string, error) { return 999, "123", nil }}
}
func (f *fixture) guard() guard {
	return guard{f.fs, f.f, f.load, f.clock, func(int) (int, string, error) { return 999, "123", nil }, func(_ protectedFS, _ authority, id, mode string, _ nativeapt.Invocation) (processRecord, *os.File, error) {
		lock, e := os.Open(filepath.Join(f.fs.root, "guard-fixture-lock"))
		return processRecord{888, "456", mode}, lock, e
	}}
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	f := &fixture{t: t, fs: protectedFS{root, uint32(os.Getuid())}, f: &fakeFence{}, c: &fakeCommands{}, now: testNow}
	f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub := f.key.Public().(ed25519.PublicKey)
	p := Policy{Version: PolicyVersion, Enabled: true, NativeAcceptanceDigest: actionpermit.Digest([]byte("invented-fixture-only")), ManagerID: "manager_" + strings.Repeat("2", 32), EndpointID: "agent_" + strings.Repeat("a", 32), IncarnationDigest: actionpermit.Digest([]byte("fixture-incarnation")), KeyID: actionpermit.Digest(pub), TransportProfile: "production-tls", AgentUID: 1001, AgentGID: 1001, Allowed: []packagepermit.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	for i, path := range requiredTools {
		b := []byte(fmt.Sprintf("fixture-nonexecutable-%d", i))
		if path == RunnerUnitPath {
			b = runnerUnitTemplate
		}
		f.write(path, b)
		p.Tools = append(p.Tools, ToolPin{path, actionpermit.Digest(b)})
	}
	receipt := []byte("tracebolt-service-helper-shared-fence-v1\n" + p.Tools[0].Digest + "\nlegacy-helper-quiescent-before-initialization\n")
	f.write(nativeapt.PolicyDirectory+"/service-fence-reviewed", receipt)
	p.ServiceFenceReviewDigest = actionpermit.Digest(receipt)
	policy, _ := json.Marshal(p)
	f.write(PolicyPath, policy)
	f.write(PublicKeyPath, pub)
	f.a = authority{p, policy, pub, actionpermit.Digest(policy)}
	f.mkdir("/etc/apt/apt.conf.d")
	f.mkdir("/etc/dpkg/dpkg.cfg.d")
	host, _ := nativeapt.ConfigSnapshotDigest(nil)
	f.write(nativeapt.PolicyDirectory+"/native-opt-in", []byte("tracebolt-reviewed-isolated-apt-config-debian13-amd64-v1\n"+host+"\n"))
	for _, n := range []string{"sources.sources", "preferences", "keyring.gpg"} {
		b := []byte("fixture " + n)
		if n == "preferences" {
			b = nil
		}
		f.write(nativeapt.PolicyDirectory+"/"+n, b)
	}
	f.mkdir(nativeapt.JobRoot)
	f.json(nativeapt.JobRoot+"/binding.json", stateBinding{StateVersion, binding(f.a)})
	f.write(nativeapt.JobRoot+"/broker.lock", nil)
	f.write("/guard-fixture-lock", nil)
	f.p = packagepermit.Permit{Version: packagepermit.Version, Action: packagepermit.Prepare, ManagerID: p.ManagerID, KeyID: p.KeyID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: f.a.digest, JobID: testID, Sequence: 1, ActorID: "operator_" + strings.Repeat("3", 32), IssuedAt: testNow, NotBefore: testNow, StartDeadline: testNow + 120, Selection: p.Allowed}
	var e error
	f.raw, e = packagepermit.Sign(context.Background(), f.p, f.key)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) admit() {
	f.t.Helper()
	s, e := f.broker().submit(context.Background(), f.a, f.raw)
	if e != nil || s.State != packageupdate.Preparing {
		f.t.Fatalf("admit: %v %+v", e, s)
	}
}
func (f *fixture) prepareEvidence() {
	f.t.Helper()
	status := []byte("Package: sample-bin\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\nMulti-Arch: same\nSource: sample-bin (1.0-1)\n\n")
	f.write("/var/lib/dpkg/status", status)
	f.mkdir("/var/lib/dpkg/updates")
	f.write("/var/lib/dpkg/triggers/Unincorp", nil)
	f.write("/var/lib/dpkg/lock", nil)
	f.write("/var/lib/dpkg/lock-frontend", nil)
	f.mkdir("/run")
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		f.t.Fatal(e)
	}
	plan, e := packageplan.Decode(context.Background(), raw)
	if e != nil {
		f.t.Fatal(e)
	}
	paths, _ := nativeapt.JobPaths(testID)
	archive := []byte("invented test archive only")
	plan.Packages[0].Archive.SHA256 = actionpermit.Digest(archive)
	plan.Packages[0].Archive.Size = uint64(len(archive))
	f.write(paths.Archives+"/sample-bin_1.0-2_amd64.deb", archive)
	f.mkdir(paths.Snapshot + "/empty")
	f.write(paths.Snapshot+"/empty.conf", nil)
	for _, n := range []string{"sources.sources", "preferences", "keyring.gpg"} {
		b, e := f.fs.read(nativeapt.PolicyDirectory+"/"+n, 1024)
		if e != nil {
			f.t.Fatal(e)
		}
		f.write(paths.Snapshot+"/"+n, b)
	}
	host, source, e := f.fs.configuration()
	if e != nil {
		f.t.Fatal(e)
	}
	d := actionpermit.Digest(status)
	a := plan.Packages[0].Archive
	f.prepared = nativeapt.Prepared{Version: nativeapt.BundleVersion, UpdateID: testID, APTVersion: nativeapt.SupportedAPTVersion, MetadataRefreshedAt: testNow - 5, InventoryAt: testNow, InventoryDigest: d, DpkgStateDigest: d, HoldsDigest: actionpermit.Digest(nil), SourceSnapshotDigest: source, HostConfigDigest: host, APTConfigDigest: actionpermit.Digest(nativeapt.ConfigBytes(paths, testID)), Packages: plan.Packages, Sources: []nativeapt.Source{{IdentityDigest: a.SourceIdentityDigest, Label: "FIXTURE Debian", Suite: "trixie", Component: "main"}}, Archives: []nativeapt.StagedArchive{{Path: paths.Archives + "/sample-bin_1.0-2_amd64.deb", SHA256: a.SHA256, Size: a.Size}}}
	f.json(paths.Prepared, f.prepared)
	hook, e := os.ReadFile("../packageplan/testdata/single.hook")
	if e != nil {
		f.t.Fatal(e)
	}
	f.hook = bytes.ReplaceAll(hook, []byte("/var/cache/apt/archives"), []byte(paths.Archives))
	f.json(jobFile(testID, "prepare.claim"), runnerClaim{"prepare", 999, "123", testNow})
	f.json(jobFile(testID, "prepare.apt"), processRecord{888, "456", "prepare"})
}
func (f *fixture) capture() {
	f.t.Helper()
	if code := f.guard().run(testID, bytes.NewReader(f.hook)); code != CaptureAbortExit {
		f.t.Fatalf("capture code=%d", code)
	}
	var receipt captureReceipt
	if e := f.fs.json(jobFile(testID, "capture.receipt"), packageplanMaxBytes, &receipt); e != nil {
		f.t.Fatal(e)
	}
	if e := f.f.Complete(context.Background(), owner(f.p, f.raw), "not_started", f.now); e != nil {
		f.t.Fatal(e)
	}
	f.json(jobFile(testID, "preview.json"), receipt.Preview)
}
func (f *fixture) approve() {
	f.t.Helper()
	var preview packageupdate.Preview
	if e := f.fs.json(jobFile(testID, "preview.json"), packageplanMaxBytes, &preview); e != nil {
		f.t.Fatal(e)
	}
	p := f.p
	p.Action = packagepermit.Execute
	p.Plan = &preview.Plan
	p.PlanDigest = preview.PlanDigest
	p.PreviewDigest = preview.Digest
	p.StartDeadline = preview.Plan.ExpiresAt
	raw, e := packagepermit.Sign(context.Background(), p, f.key)
	if e != nil {
		f.t.Fatal(e)
	}
	if _, e = f.broker().submit(context.Background(), f.a, raw); e != nil {
		f.t.Fatal(e)
	}
	f.p = p
	f.raw = raw
}
func TestProtectedAuthorityAndNoFollow(t *testing.T) {
	f := newFixture(t)
	if _, e := f.fs.authority(); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(f.fs.root, PublicKeyPath)
	if e := os.Chmod(p, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := f.fs.authority(); e == nil {
		t.Fatal("writable key accepted")
	}
	_ = os.Chmod(p, 0600)
	if e := os.Rename(p, p+".original"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(p+".original", p); e != nil {
		t.Fatal(e)
	}
	if _, e := f.fs.authority(); e == nil {
		t.Fatal("symlink key accepted")
	}
}
func TestProtectedFilesRejectHardlinksAndWriteOnce(t *testing.T) {
	f := newFixture(t)
	p := "/once"
	if e := f.fs.create(p, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := f.fs.create(p, []byte("second")); e == nil {
		t.Fatal("overwrite")
	}
	if e := os.Link(filepath.Join(f.fs.root, p), filepath.Join(f.fs.root, "other")); e != nil {
		t.Fatal(e)
	}
	if _, e := f.fs.read(p, 100); e == nil {
		t.Fatal("hardlink accepted")
	}
}
func TestBrokerPersistsBeforeSingleLaunchAndRetry(t *testing.T) {
	f := newFixture(t)
	f.c.fn = func(s commandSpec) (commandResult, error) {
		if s.executable != SystemctlExecutable || !strings.Contains(strings.Join(s.args, " "), testID) {
			t.Fatal("unfixed command")
		}
		if _, e := f.fs.read(jobFile(testID, "prepare.admitted"), 4096); e != nil {
			t.Fatal("launch before durable admission")
		}
		if len(f.f.entries) != 1 {
			t.Fatal("launch before shared consume")
		}
		return commandResult{started: true, exit: 0}, nil
	}
	f.admit()
	if len(f.c.specs) != 1 {
		t.Fatal("start count")
	}
	f.now += 500
	if _, e := f.broker().submit(context.Background(), f.a, f.raw); e != nil {
		t.Fatal(e)
	}
	if len(f.c.specs) != 1 {
		t.Fatal("replay launched")
	}
	p := f.p
	p.Sequence++
	raw, _ := packagepermit.Sign(context.Background(), p, f.key)
	if _, e := f.broker().submit(context.Background(), f.a, raw); e == nil {
		t.Fatal("changed permit accepted")
	}
}
func TestLostStartResponseNeverRestarts(t *testing.T) {
	f := newFixture(t)
	f.c.fn = func(commandSpec) (commandResult, error) { return commandResult{started: true, exit: -1}, ErrUncertain }
	if _, e := f.broker().submit(context.Background(), f.a, f.raw); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	if _, e := f.broker().submit(context.Background(), f.a, f.raw); e != nil {
		t.Fatal(e)
	}
	if len(f.c.specs) != 1 || f.f.entries[0].CompletedAt != 0 {
		t.Fatal("uncertainty cleared")
	}
}
func TestCaptureAlwaysAbortsCompleteReceiptAndRepeatedHookRefuses(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	if code := f.guard().run(testID, bytes.NewReader(f.hook)); code == 0 || code == CaptureAbortExit {
		t.Fatal("repeated hook accepted")
	}
	var receipt captureReceipt
	if e := f.fs.json(jobFile(testID, "capture.receipt"), packageplanMaxBytes, &receipt); e != nil {
		t.Fatal(e)
	}
	if receipt.HookDigest != actionpermit.Digest(f.hook) || receipt.Preview.Plan.Evidence.ConfigDigest == "" || receipt.Preview.Sources[0].Label != "FIXTURE Debian" {
		t.Fatal("incomplete capture")
	}
	if yes, _ := f.fs.exists(jobFile(testID, "execute.guard-admitted")); yes {
		t.Fatal("capture granted dpkg")
	}
}
func TestGuardRejectsChangedArchiveStatusPolicyAndExpiry(t *testing.T) {
	for _, which := range []string{"archive", "status", "config", "expiry", "parent", "rawhook"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t)
			f.admit()
			f.prepareEvidence()
			f.capture()
			f.approve()
			f.json(jobFile(testID, "execute.claim"), runnerClaim{"execute", 999, "123", testNow})
			g := f.guard()
			hook := f.hook
			switch which {
			case "archive":
				f.write(f.prepared.Archives[0].Path, []byte("altered"))
			case "status":
				f.write("/var/lib/dpkg/status", []byte("not a database"))
			case "config":
				f.write("/etc/dpkg/dpkg.cfg", []byte("force-confnew\n"))
			case "expiry":
				f.now += 120
			case "parent":
				g.prove = func(protectedFS, authority, string, string, nativeapt.Invocation) (processRecord, *os.File, error) {
					return processRecord{}, nil, ErrRejected
				}
			case "rawhook":
				hook = bytes.ReplaceAll(hook, []byte("1.0-2"), []byte("1.0-3"))
			}
			if code := g.run(testID, bytes.NewReader(hook)); code == 0 {
				t.Fatal("guard allowed altered input")
			}
			if yes, _ := f.fs.exists(jobFile(testID, "execute.guard-admitted")); yes {
				t.Fatal("guard admission exists")
			}
		})
	}
}
func TestExecuteGuardSingleUseAndApplyingMarker(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	f.approve()
	f.json(jobFile(testID, "execute.claim"), runnerClaim{"execute", 999, "123", testNow})
	if code := f.guard().run(testID, bytes.NewReader(f.hook)); code != 0 {
		t.Fatalf("guard rejected %d", code)
	}
	if code := f.guard().run(testID, bytes.NewReader(f.hook)); code == 0 {
		t.Fatal("guard replay")
	}
	s, e := f.fs.snapshot(testID)
	if e != nil || s.State != packageupdate.Applying || s.Result.Reboot.Source != "native" {
		t.Fatal(e, s)
	}
	if f.f.entries[1].CompletedAt != 0 {
		t.Fatal("guard prematurely completed fence")
	}
}
func TestExecutionHasNoTimeoutVerifiesAndCompletes(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	f.approve()
	f.c.specs = nil
	f.c.fn = func(s commandSpec) (commandResult, error) {
		if s.executable != nativeapt.APTExecutable || s.timeout != 0 {
			t.Fatal("applying timeout or command")
		}
		inv, _ := invocation(testID, f.prepared)
		if !rawEqual(s.args, inv.Args) || !rawEqual(s.env, inv.Env) {
			t.Fatal("capture/execution differ")
		}
		if code := f.guard().run(testID, bytes.NewReader(f.hook)); code != 0 {
			t.Fatal("guard", code)
		}
		b, _ := f.fs.read("/var/lib/dpkg/status", 64<<20)
		f.write("/var/lib/dpkg/status", bytes.ReplaceAll(b, []byte("1.0-1"), []byte("1.0-2")))
		return commandResult{started: true, exit: 0}, nil
	}
	if e := f.runner().run(testID); e != nil {
		t.Fatal(e)
	}
	s, e := f.fs.snapshot(testID)
	if e != nil || s.State != packageupdate.Succeeded || len(s.Results) != 3 || s.Result.Reboot.State != "not_reported" || f.f.entries[1].CompletedAt == 0 {
		t.Fatal(e, s)
	}
	if e = f.runner().run(testID); e == nil {
		t.Fatal("runner replay")
	}
	if len(f.c.specs) != 1 {
		t.Fatal("runner repeated process")
	}
}
func TestMissingGuardCannotSucceedAndKeepsFence(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	f.approve()
	f.c.fn = func(commandSpec) (commandResult, error) { return commandResult{started: true, exit: 0}, nil }
	if e := f.runner().run(testID); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	s, e := f.fs.snapshot(testID)
	if e != nil || s.State != packageupdate.NeedsIntervention || f.f.entries[1].CompletedAt != 0 {
		t.Fatal(e, s)
	}
}
func TestCaptureExit100WithoutReceiptIsFailure(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence() // existing fixture claim would deliberately block RunRunner; test only private prepare seam.
	f.c.fn = func(s commandSpec) (commandResult, error) {
		if s.executable == nativeapt.NativeExecutable {
			return commandResult{started: true, exit: 0}, nil
		}
		return commandResult{started: true, exit: 100}, errors.New("fixture apt refusal")
	}
	if e := f.runner().prepare(f.a, f.raw, f.p); e == nil {
		t.Fatal("exit100 trusted")
	}
	s, e := f.fs.snapshot(testID)
	if e != nil || s.State != packageupdate.PreparationFailed {
		t.Fatal(e, s)
	}
	if f.f.entries[0].Outcome != "not_started" {
		t.Fatal("nonmutating refusal not retained")
	}
}
func TestProtocolStrictBoundsAndUnsupportedOperations(t *testing.T) {
	f := newFixture(t)
	q := Request{Version: RequestVersion, Operation: SubmitOperation, Envelope: f.raw}
	b, e := EncodeRequest(q)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = readRequest(bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{frame([]byte(`{"version":"tracebolt.package-helper-request.v1","operation":"capabilities","unknown":1}`)), frame(bytes.Repeat([]byte("a"), MaxRequestBytes+1)), frame([]byte(`{"version":"tracebolt.package-helper-request.v1","operation":"initialize"}`))} {
		if _, e := readRequest(bytes.NewReader(bad)); e == nil {
			t.Fatal("bad request accepted")
		}
	}
}
func TestPendingDPKGAndUnsupportedConfigsRefuse(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	for _, bad := range []string{"Status: install reinstreq installed", "Status: install ok triggers-pending", "Status: install ok unpacked"} {
		raw, _ := f.fs.read("/var/lib/dpkg/status", 64<<20)
		raw = bytes.ReplaceAll(raw, []byte("Status: install ok installed"), []byte(bad))
		if _, e := parseStatus(raw); e == nil {
			t.Fatal("dirty dpkg accepted", bad)
		}
	}
	f.write("/var/lib/dpkg/updates/0000", []byte("pending"))
	if _, e := f.fs.dpkg(); e == nil {
		t.Fatal("pending update accepted")
	}
}
func TestInterruptedRecordIntentCannotBeAdopted(t *testing.T) {
	f := newFixture(t)
	f.write("/record", []byte("looks-complete"))
	f.write("/record.intent", []byte("pending"))
	if _, e := f.fs.read("/record", 100); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	if e := f.fs.create("/record", []byte("new")); e == nil {
		t.Fatal("interrupted overwrite")
	}
}
func TestDeadRunnerBecomesInterventionWithoutRestartOrFenceRelease(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	f.approve()
	f.json(jobFile(testID, "execute.claim"), runnerClaim{"execute", 999, "123", testNow})
	before := len(f.c.specs)
	s, e := f.broker().status(testID, func(runnerClaim) bool { return false })
	if e != nil || s.State != packageupdate.NeedsIntervention {
		t.Fatal(e, s)
	}
	if f.f.entries[1].CompletedAt != 0 {
		t.Fatal("interrupted fence released")
	}
	if len(f.c.specs) != before+1 || f.c.specs[before].args[0] != "show" {
		t.Fatal("restarted dead runner")
	}
}
func TestStillActivePrepareRefusesExecuteBeforeConsumption(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	var p packageupdate.Preview
	if e := f.fs.json(jobFile(testID, "preview.json"), packageplanMaxBytes, &p); e != nil {
		t.Fatal(e)
	}
	q := f.p
	q.Action = packagepermit.Execute
	q.Plan = &p.Plan
	q.PlanDigest = p.PlanDigest
	q.PreviewDigest = p.Digest
	raw, e := packagepermit.Sign(context.Background(), q, f.key)
	if e != nil {
		t.Fatal(e)
	}
	f.c.fn = func(commandSpec) (commandResult, error) {
		return commandResult{exit: 0, stdout: []byte("active\n")}, nil
	}
	if _, e = f.broker().submit(context.Background(), f.a, raw); e == nil {
		t.Fatal("active unit accepted")
	}
	if len(f.f.entries) != 1 {
		t.Fatal("execute consumed before unit ready")
	}
	if yes, _ := f.fs.exists(jobFile(testID, "execute.permit")); yes {
		t.Fatal("execute consumed")
	}
}
func TestFenceCompletionFailureCannotPublishSuccess(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	f.approve()
	f.f.failComplete = true
	f.c.fn = func(commandSpec) (commandResult, error) {
		if code := f.guard().run(testID, bytes.NewReader(f.hook)); code != 0 {
			t.Fatal(code)
		}
		raw, _ := f.fs.read("/var/lib/dpkg/status", 64<<20)
		f.write("/var/lib/dpkg/status", bytes.ReplaceAll(raw, []byte("1.0-1"), []byte("1.0-2")))
		return commandResult{started: true, exit: 0}, nil
	}
	if e := f.runner().run(testID); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	s, e := f.fs.snapshot(testID)
	if e != nil || s.State != packageupdate.NeedsIntervention || f.f.entries[1].CompletedAt != 0 {
		t.Fatal(e, s)
	}
}
func TestRealisticDPKGConffilesMultilineHeader(t *testing.T) {
	raw := []byte("Package: sample-bin\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\nConffiles:\n /etc/sample.conf d41d8cd98f00b204e9800998ecf8427e\nDescription: Fixture first line\n more description\n .\n another paragraph\n\n")
	s, e := parseStatus(raw)
	if e != nil || s.packages["sample-bin:amd64"].version != "1.0-1" {
		t.Fatal(e)
	}
	if _, e = parseStatus(bytes.ReplaceAll(raw, []byte("Version: 1.0-1\n"), []byte("Version: 1.0-1\n fake extension\n"))); e == nil {
		t.Fatal("folded identity field accepted")
	}
}
func TestBusyRejectionLeavesNoJobAndCanAdmitWhenFree(t *testing.T) {
	f := newFixture(t)
	block := mutationfence.Owner{Action: mutationfence.Service, JobID: "action_" + strings.Repeat("9", 32), Sequence: 1, EnvelopeDigest: actionpermit.Digest([]byte("fixture-service"))}
	_, _, _ = f.f.Acquire(context.Background(), block, f.now)
	if _, e := f.broker().submit(context.Background(), f.a, f.raw); !errors.Is(e, mutationfence.ErrBusy) {
		t.Fatal(e)
	}
	if _, e := f.fs.read(jobFile(testID, "prepare.permit"), packagepermit.MaxEnvelopeBytes); !os.IsNotExist(e) {
		t.Fatal("busy request published", e)
	}
	_ = f.f.Complete(context.Background(), block, "completed", f.now)
	f.admit()
	if len(f.c.specs) != 1 {
		t.Fatal("start count")
	}
}
func TestPreclaimFailureReconcilesBothModesWithoutReleasingFence(t *testing.T) {
	for _, mode := range []string{"prepare", "execute"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.admit()
			if mode == "execute" {
				f.prepareEvidence()
				f.capture()
				f.approve()
			}
			s, e := f.broker().status(testID, func(runnerClaim) bool { return false })
			if e != nil || s.State != packageupdate.NeedsIntervention {
				t.Fatal(e, s)
			}
			last := f.f.entries[len(f.f.entries)-1]
			if last.CompletedAt != 0 {
				t.Fatal("unknown fence released")
			}
			if mode == "prepare" && (s.ExecutionEnvelopeDigest != "" || len(s.Results) != 0) {
				t.Fatal("fabricated execution")
			}
		})
	}
}
func TestPendingSystemdJobCannotBeCalledInterrupted(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.c.fn = func(commandSpec) (commandResult, error) {
		return commandResult{exit: 0, stdout: []byte("MainPID=0\nActiveState=inactive\nJob=123\n")}, nil
	}
	s, e := f.broker().status(testID, func(runnerClaim) bool { return false })
	if e != nil || s.State != packageupdate.Preparing {
		t.Fatal(e, s)
	}
}
func TestAgentReplacementDoesNotHideAlreadyAdmittedCompletion(t *testing.T) {
	f := newFixture(t)
	f.admit()
	f.prepareEvidence()
	f.capture()
	f.approve()
	r := f.runner()
	r.load = f.fs.authority
	f.c.fn = func(commandSpec) (commandResult, error) {
		if code := f.guard().run(testID, bytes.NewReader(f.hook)); code != 0 {
			t.Fatal(code)
		}
		f.write(ServiceHelperExecutable, []byte("replacement fixture agent"))
		raw, _ := f.fs.read("/var/lib/dpkg/status", 64<<20)
		f.write("/var/lib/dpkg/status", bytes.ReplaceAll(raw, []byte("1.0-1"), []byte("1.0-2")))
		return commandResult{started: true, exit: 0}, nil
	}
	if e := r.run(testID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.fs.authority(); e == nil {
		t.Fatal("changed tool admitted")
	}
	s, e := f.broker().status(testID, func(runnerClaim) bool { return false })
	if e != nil || s.State != packageupdate.Succeeded {
		t.Fatal(e, s)
	}
	p := f.a.policy
	p.Enabled = false
	f.json(PolicyPath, p)
	if s, e = f.broker().status(testID, func(runnerClaim) bool { return false }); e != nil || s.State != packageupdate.Succeeded {
		t.Fatal("policy disable hid history", e)
	}
	p.EndpointID = "agent_" + strings.Repeat("b", 32)
	f.json(PolicyPath, p)
	if _, e = f.broker().status(testID, func(runnerClaim) bool { return false }); e == nil {
		t.Fatal("history leaked to rebound endpoint")
	}
}
func TestFirstPilotExcludesPackageManagerAndHostFoundations(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"apt", "apt-utils", "dpkg", "libapt-pkg7.0", "libc6", "libc6-dev", "libc-bin", "systemd", "systemd-resolved", "linux-image-amd64", "kernel-tools", "grub-common", "openssh-server", "iproute2", "network-manager", "tracebolt-agent", "localrmm"} {
		p := f.a.policy
		p.Allowed = []packagepermit.Selection{{Name: name, Architecture: "amd64"}}
		raw, _ := json.Marshal(p)
		if _, e := DecodePolicy(raw, f.a.key); e == nil {
			t.Fatal("foundation allowed", name)
		}
	}
}

type directFakeCommands func(commandSpec) (commandResult, error)

func (f directFakeCommands) run(s commandSpec) (commandResult, error) { return f(s) }
func TestRunnerUnitPinnedExactAndEffectiveDefinitionCannotDrift(t *testing.T) {
	f := newFixture(t)
	if _, e := f.fs.authority(); e != nil {
		t.Fatal(e)
	}
	template, e := os.ReadFile("../../deploy/package-actions/tracebolt-package-runner@.service.in")
	if e != nil || !bytes.Equal(template, runnerUnitTemplate) {
		t.Fatal("template drift", e)
	}
	for _, bad := range []string{"DropInPaths=/etc/systemd/system/service.d/agent.conf", "NeedDaemonReload=yes", "Slice=agent.service", "FragmentPath=/run/systemd/transient/evil.service"} {
		c := directFakeCommands(func(s commandSpec) (commandResult, error) {
			v := map[string]string{"FragmentPath": RunnerUnitPath, "DropInPaths": "", "NeedDaemonReload": "no", "Slice": "system.slice"}
			key, value, _ := strings.Cut(bad, "=")
			v[key] = value
			var out strings.Builder
			for _, k := range []string{"FragmentPath", "DropInPaths", "NeedDaemonReload", "Slice"} {
				fmt.Fprintf(&out, "%s=%s\n", k, v[k])
			}
			return commandResult{exit: 0, stdout: []byte(out.String())}, nil
		})
		if runnerDefinition(c, testID) {
			t.Fatal("unreviewed unit accepted", bad)
		}
	}
	f.write(RunnerUnitPath, append(bytes.Clone(runnerUnitTemplate), []byte("\nPartOf=tracebolt-agent.service\n")...))
	if _, e = f.fs.authority(); e == nil {
		t.Fatal("changed unit accepted")
	}
}

func TestCurrentProcessMustHoldExactSharedFenceInode(t *testing.T) {
	f := newFixture(t)
	f.write(mutationfence.DefaultDirectory+"/fence.lock", nil)
	_, start, e := procIdentity(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	// The supplied process start identity is checked independently of its FDs.
	if processHoldsMutationFence(f.fs, os.Getpid(), "different-start") == nil {
		t.Fatal("PID reuse accepted")
	}
	hold, _, e := f.fs.open(mutationfence.DefaultDirectory+"/fence.lock", mutationfence.MaxBytes)
	if e != nil {
		t.Fatal(e)
	}
	defer hold.Close()
	if e = processHoldsMutationFence(f.fs, os.Getpid(), start); e != nil {
		t.Fatal(e)
	}
}
