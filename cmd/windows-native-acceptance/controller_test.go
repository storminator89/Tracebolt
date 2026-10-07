package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
	"math/big"
	"strings"
	"testing"
	"time"
)

// All observations are injected in-memory. No listener, Windows object, persistent
// identity, privilege, filesystem ACL or native process is created by these tests.
type fakePeer struct {
	b                    enrollmentclient.Bootstrap
	e                    fixture.Evidence
	approved, closeError bool
	closeHook            func()
}

func (f *fakePeer) Bootstrap() enrollmentclient.Bootstrap  { return f.b }
func (f *fakePeer) Secret(context.Context) ([]byte, error) { return []byte("memory-fixture"), nil }
func (f *fakePeer) Approve(fp, code string) error {
	if fp != strings.Repeat("b", 64) || code != "fixture-comparison" {
		return errors.New("approval mismatch")
	}
	f.approved = true
	return nil
}
func (f *fakePeer) Evidence() fixture.Evidence { return f.e }
func (f *fakePeer) ToggleUnavailable(v bool)   { f.e.Unavailable = v }
func (f *fakePeer) Close() error {
	if f.closeHook != nil {
		f.closeHook()
	}
	f.e.Closed = true
	if f.closeError {
		return errors.New("fixture close")
	}
	return nil
}

type fakeDriver struct {
	e                   native.Evidence
	peer                *fakePeer
	calls               []string
	fail, omit          string
	pendingObservations int
}

func (d *fakeDriver) call(n string) error {
	d.calls = append(d.calls, n)
	if d.fail == n {
		d.e.Reason = native.ReasonOperation
		return native.ErrAcceptance
	}
	return nil
}
func (d *fakeDriver) Evidence() native.Evidence { return d.e }
func (d *fakeDriver) Preflight(context.Context) error {
	d.e.Stage = native.StagePreflight
	if d.call("preflight") != nil {
		d.e.Reason = native.ReasonPrerequisite
		return native.ErrAcceptance
	}
	d.e.Prerequisites = true
	return nil
}
func (d *fakeDriver) Provision(context.Context, native.Guard) error {
	if d.call("provision") != nil {
		return native.ErrAcceptance
	}
	d.e.Provisioned = true
	return nil
}
func (d *fakeDriver) Prepare(context.Context, native.Guard, []byte) error {
	d.e.Installed = true
	if d.call("prepare") != nil {
		return native.ErrAcceptance
	}
	d.e.Prepared = true
	return nil
}
func (d *fakeDriver) Claim(_ context.Context, _ native.Guard, _ func(context.Context) ([]byte, error), display func(enrollmentclient.TrustDisplay) error) error {
	if d.call("claim") != nil {
		return native.ErrAcceptance
	}
	b := d.peer.b
	if d.omit != "display" {
		if err := display(enrollmentclient.TrustDisplay{HTTPTest: b.Profile == "http-test", Profile: b.Profile, CollectionProfile: b.CollectionProfile, ManagerInstanceID: b.ManagerInstanceID, EnrollmentOrigin: b.EnrollmentOrigin, AgentOrigin: b.AgentOrigin, InvitationID: b.InvitationID, ServerCAFingerprints: fixtureServerPins(b.ServerCAPEM), IssuerRootFingerprint: certificateHash(b.IssuerRootPEM), IssuerFingerprint: certificateHash(b.IssuerPEM), KeyFingerprint: strings.Repeat("b", 64), ComparisonCode: "fixture-comparison"}); err != nil {
			return err
		}
	}
	d.e.ClaimCommitted = true
	return nil
}
func (d *fakeDriver) Start(context.Context, native.Guard) error {
	if d.call("start") != nil {
		return native.ErrAcceptance
	}
	d.e.Running = true
	d.e.Stopped = false
	return nil
}
func (d *fakeDriver) InspectToken(context.Context) error {
	if d.call("token") != nil {
		return native.ErrAcceptance
	}
	d.e.LimitedToken = d.omit != "token"
	return nil
}
func (d *fakeDriver) Status(context.Context) error { return d.call("status") }
func (d *fakeDriver) Stop(context.Context, native.Guard) error {
	if d.call("stop") != nil {
		return native.ErrAcceptance
	}
	d.e.Running = false
	d.e.Stopped = true
	return nil
}
func (d *fakeDriver) StateContinuity(context.Context) error {
	if d.call("continuity") != nil {
		return native.ErrAcceptance
	}
	d.e.IdentityRetained = true
	d.e.Ready = d.peer.approved
	if d.peer.approved {
		d.e.SenderFloorRetained = true
	}
	d.e.PendingPresent = d.peer.e.Unavailable
	if d.e.PendingPresent {
		d.pendingObservations++
		if d.pendingObservations > 1 {
			d.e.PendingBytesRetained = d.omit != "pending-bytes"
		}
	}
	return nil
}
func (d *fakeDriver) Probe(context.Context, native.Guard) error {
	if d.call("probe") != nil {
		return native.ErrAcceptance
	}
	d.e.UnrelatedServiceDenied = d.omit != "denial"
	return nil
}
func (d *fakeDriver) Uninstall(context.Context, native.Guard) error {
	if d.call("uninstall") != nil {
		return native.ErrAcceptance
	}
	d.e.Uninstalled = true
	d.e.Installed = false
	d.e.UninstallStateRetained = true
	return nil
}
func (d *fakeDriver) Cleanup(context.Context, native.Guard) error {
	d.e.Stage = native.StageCleanup
	if d.call("cleanup") != nil || d.e.Installed && !d.e.Uninstalled {
		d.e.CleanupRetained = true
		return native.ErrAcceptance
	}
	d.e.Cleaned = true
	d.e.Reason = native.ReasonNone
	return nil
}
func controllerFixture(t *testing.T) (*gate.Grant, *fakeDriver, *fakePeer, controllerHooks) {
	t.Helper()
	sha := strings.Repeat("a", 40)
	g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: profile.BasicTLS()}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	f := &fakePeer{e: fixture.Evidence{Inventory: profile.ZeroObservation(), Transport: "tls"}, b: enrollmentclient.Bootstrap{Profile: "tls", CollectionProfile: "basic-readonly-v1", ManagerInstanceID: "fixture-manager", InvitationID: "fixture-invitation", EnrollmentOrigin: "https://127.0.0.1:32100", AgentOrigin: "https://127.0.0.1:32101", ServerCAPEM: cert, IssuerRootPEM: cert, IssuerPEM: cert}}
	d := &fakeDriver{e: native.Evidence{Stage: native.StageIdle, Reason: native.ReasonNone}, peer: f}
	now := time.Unix(0, 0)
	h := controllerHooks{newDriver: func(native.Options) (driver, error) { return d, nil }, startPeer: func(context.Context, profile.Selection) (peer, error) {
		d.calls = append(d.calls, "fixture-start")
		return f, nil
	}, now: func() time.Time { return now }, pause: func(c context.Context, duration time.Duration) error {
		if c.Err() != nil {
			return c.Err()
		}
		now = now.Add(duration)
		if d.e.Running && f.approved {
			if f.e.Unavailable {
				f.e.UnavailableRequests++
			} else {
				f.e.Frames++
				f.e.LastSequence++
				f.e.Platform = "windows"
				f.e.CollectionProfile = f.b.CollectionProfile
				f.e.Transport = f.b.Profile
				if f.b.CollectionProfile == "windows-inventory-v1" {
					f.e.Inventory = usableInventory(f.e.Frames)
				}
			}
		}
		return nil
	}}
	return g, d, f, h
}
func TestControllerSyntheticCompleteSequence(t *testing.T) {
	g, d, f, h := controllerFixture(t)
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.Status != "passed_native_subset" || gate.Validate(r) != nil || !f.e.Closed {
		t.Fatal("synthetic sequence failed")
	}
	if r.ProductionManagerExercised || r.OSShutdownExercised || r.OSRebootExercised || r.HiddenConsoleExercised {
		t.Fatal("fixture overclaimed native scope")
	}
	if strings.Join(d.calls, ",") != "preflight,provision,fixture-start,prepare,claim,start,token,stop,continuity,start,stop,continuity,probe,start,stop,continuity,start,stop,continuity,start,stop,continuity,uninstall,cleanup" {
		t.Fatalf("unexpected finite call sequence: %v", d.calls)
	}
}
func TestControllerAncestorFailureNeverProvisionsOrStartsPeer(t *testing.T) {
	g, d, _, h := controllerFixture(t)
	d.fail = "preflight"
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.Status != "blocked" || r.NativeActionsAttempted || gate.Validate(r) != nil || strings.Join(d.calls, ",") != "preflight" {
		t.Fatal("prerequisite bypass")
	}
}
func TestControllerFailureStopsUninstallsAndCleansOnlyOwnedReceipt(t *testing.T) {
	g, d, f, h := controllerFixture(t)
	d.fail = "claim"
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.Status != "failed" || !r.Native.Cleaned || !r.Native.Uninstalled || !f.e.Closed || !strings.HasSuffix(strings.Join(d.calls, ","), "claim,cleanup-stop,uninstall,cleanup") {
		t.Fatal("failure cleanup incomplete")
	}
}
func TestControllerPartialProvisionFailureStillRequestsBoundedCleanup(t *testing.T) {
	g, d, _, h := controllerFixture(t)
	d.fail = "provision"
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.Status != "failed" || strings.Join(d.calls, ",") != "preflight,provision,cleanup" {
		t.Fatal("partial provision cleanup adopted a service")
	}
}
func TestControllerMissingNativeEvidenceNeverPassesValidation(t *testing.T) {
	for _, omit := range []string{"token", "denial", "pending-bytes", "display"} {
		t.Run(omit, func(t *testing.T) {
			g, d, _, h := controllerFixture(t)
			d.omit = omit
			r := executeWith(context.Background(), g, native.Options{}, h)
			if r.Status == "passed_native_subset" && gate.Validate(r) == nil {
				t.Fatal("missing independent proof accepted")
			}
		})
	}
}
func TestControllerCloseFailureCannotPass(t *testing.T) {
	g, _, f, h := controllerFixture(t)
	f.closeError = true
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.Status != "failed" || r.Stage != "owned_cleanup" {
		t.Fatal("fixture remained alive after claimed success")
	}
}
func TestControllerRevokedGrantIsInert(t *testing.T) {
	g, d, _, h := controllerFixture(t)
	g.Close()
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.NativeActionsAttempted || len(d.calls) != 0 {
		t.Fatal("revoked scope used")
	}
}
func TestControllerCancelledWaitStillUsesBoundedOwnedCleanup(t *testing.T) {
	g, d, f, h := controllerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.pause = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	r := executeWith(ctx, g, native.Options{}, h)
	if r.Status != "failed" || !r.Native.Cleaned || !f.e.Closed || !strings.HasSuffix(strings.Join(d.calls, ","), "cleanup-stop,uninstall,cleanup") {
		t.Fatal("cancel failed to retain cleanup authority")
	}
}

func (d *fakeDriver) CleanupStop(context.Context, native.Guard) error {
	if d.call("cleanup-stop") != nil {
		return native.ErrAcceptance
	}
	d.e.Running = false
	d.e.Stopped = true
	return nil
}

func fixtureServerPins(raw string) []string {
	if raw == "" {
		return nil
	}
	return []string{certificateHash(raw)}
}
func usableInventory(frames uint64) profile.Observation {
	return profile.Observation{Frames: frames, CPU: "healthy", Memory: "healthy", Disk: "healthy", Hostname: "healthy", Processes: "partial", Services: "healthy", Software: "healthy", Interfaces: "healthy"}
}

func TestControllerInventoryTLSAndExplicitHTTPUseExactGrant(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			old, d, f, h := controllerFixture(t)
			old.Close()
			selected := profile.Selection{CollectionProfile: "windows-inventory-v1", Transport: transport}
			sha := strings.Repeat("a", 40)
			g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: selected, InventoryMetadata: true, HTTPPlaintext: selected.HTTPTest()}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			f.b.Profile = transport
			f.b.CollectionProfile = selected.CollectionProfile
			f.e.Transport = transport
			if selected.HTTPTest() {
				f.b.ServerCAPEM = ""
				f.b.EnrollmentOrigin = "http://127.0.0.1:32100"
				f.b.AgentOrigin = "http://127.0.0.1:32101"
			}
			original := h.newDriver
			h.newDriver = func(o native.Options) (driver, error) {
				if o.Selection != selected {
					t.Fatal("driver did not receive exact grant")
				}
				return original(o)
			}
			r := executeWith(context.Background(), g, native.Options{}, h)
			if r.Status != "passed_native_subset" || gate.Validate(r) != nil || !r.NativeInventorySenderExercised || !r.Inventory.Usable() || !d.e.LimitedToken || r.ProductionManagerExercised || r.ProductionIngressExercised || r.SharedDashboardExercised {
				t.Fatal("inventory fixture overclaimed or failed")
			}
		})
	}
}
func TestControllerRefusesMismatchedArtifactProfileBeforeDriver(t *testing.T) {
	g, d, _, h := controllerFixture(t)
	r := executeWith(context.Background(), g, native.Options{Selection: profile.InventoryTLS()}, h)
	if r.Reason != native.ReasonGuard || len(d.calls) != 0 {
		t.Fatal("unapproved profile reached native driver")
	}
}

func TestControllerDeniedInventoryRemainsFailedWithFiniteQuality(t *testing.T) {
	old, d, f, h := controllerFixture(t)
	old.Close()
	selected := profile.InventoryTLS()
	sha := strings.Repeat("a", 40)
	g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: selected, InventoryMetadata: true}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	f.b.CollectionProfile = selected.CollectionProfile
	original := h.pause
	h.pause = func(c context.Context, d time.Duration) error {
		err := original(c, d)
		if f.e.Inventory.Frames > 0 {
			f.e.Inventory.Services = "denied"
		}
		return err
	}
	r := executeWith(context.Background(), g, native.Options{}, h)
	if r.Status != "failed" || r.Stage != "profile_report" || r.Inventory.Services != "denied" || !r.NativeInventorySenderExercised || !d.e.Cleaned || gate.Validate(r) != nil {
		t.Fatal("denied inventory counted as usable or lost cleanup")
	}
}

func TestControllerLateInventoryQualityKeepsFiniteFailure(t *testing.T) {
	for _, test := range []struct {
		quality        string
		cleanupFailure bool
	}{{"denied", false}, {"unavailable", false}, {"denied", true}} {
		name := test.quality
		if test.cleanupFailure {
			name += "/cleanup-failure"
		}
		t.Run(name, func(t *testing.T) {
			old, d, f, h := controllerFixture(t)
			old.Close()
			selected := profile.InventoryTLS()
			sha := strings.Repeat("a", 40)
			g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: selected, InventoryMetadata: true}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			f.b.CollectionProfile = selected.CollectionProfile
			if test.cleanupFailure {
				d.fail = "cleanup"
			}
			original := h.pause
			h.pause = func(c context.Context, duration time.Duration) error {
				err := original(c, duration)
				if f.e.Inventory.Frames >= 2 {
					f.e.Inventory.Services = test.quality
				}
				return err
			}
			r := executeWith(context.Background(), g, native.Options{}, h)
			if r.Status != "failed" || r.Inventory.Services != test.quality || !r.NativeInventorySenderExercised || r.Inventory.Frames < 2 {
				t.Fatal("late quality lost finite diagnostic")
			}
			if _, err := gate.Encode(r); err != nil {
				t.Fatal("late failed report could not be retained")
			}
			if test.cleanupFailure {
				if r.Stage != "owned_cleanup" || r.Reason != native.ReasonOperation || !r.Native.CleanupRetained {
					t.Fatal("cleanup failure overwritten")
				}
			} else {
				if r.Stage != "profile_report" || !d.e.Cleaned {
					t.Fatal("late quality remained a pass or lost cleanup")
				}
				for _, check := range r.Checks {
					if check.Name == "profile_report" && check.Status != "fail" {
						t.Fatal("initial quality pass not withdrawn")
					}
					if check.Name == "owned_cleanup" && check.Status != "pass" {
						t.Fatal("successful cleanup lost")
					}
				}
			}
		})
	}
}

func TestControllerFinalObservationFollowsPeerClosure(t *testing.T) {
	for _, closeFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed", true: "close-failed"}[closeFails], func(t *testing.T) {
			old, _, f, h := controllerFixture(t)
			old.Close()
			selected := profile.InventoryTLS()
			sha := strings.Repeat("a", 40)
			g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: selected, InventoryMetadata: true}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			f.b.CollectionProfile = selected.CollectionProfile
			f.closeError = closeFails
			f.closeHook = func() { f.e.Inventory.Services = "denied" }
			r := executeWith(context.Background(), g, native.Options{}, h)
			expectedStage := "profile_report"
			if closeFails {
				expectedStage = "owned_cleanup"
			}
			if r.Status != "failed" || r.Stage != expectedStage || r.Inventory.Services != "denied" || !f.e.Closed {
				t.Fatal("terminal observation preceded peer closure or hid close failure")
			}
			if _, err := gate.Encode(r); err != nil {
				t.Fatal("closed peer failure not retainable")
			}
		})
	}
}
