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
		if err := display(enrollmentclient.TrustDisplay{Profile: "tls", CollectionProfile: "basic-readonly-v1", ManagerInstanceID: b.ManagerInstanceID, EnrollmentOrigin: b.EnrollmentOrigin, AgentOrigin: b.AgentOrigin, InvitationID: b.InvitationID, ServerCAFingerprints: []string{certificateHash(b.ServerCAPEM)}, IssuerRootFingerprint: certificateHash(b.IssuerRootPEM), IssuerFingerprint: certificateHash(b.IssuerPEM), KeyFingerprint: strings.Repeat("b", 64), ComparisonCode: "fixture-comparison"}); err != nil {
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
	g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, LoopbackTLS: true, Cleanup: true}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
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
	f := &fakePeer{b: enrollmentclient.Bootstrap{ManagerInstanceID: "fixture-manager", InvitationID: "fixture-invitation", EnrollmentOrigin: "https://127.0.0.1:32100", AgentOrigin: "https://127.0.0.1:32101", ServerCAPEM: cert, IssuerRootPEM: cert, IssuerPEM: cert}}
	d := &fakeDriver{e: native.Evidence{Stage: native.StageIdle, Reason: native.ReasonNone}, peer: f}
	now := time.Unix(0, 0)
	h := controllerHooks{newDriver: func(native.Options) (driver, error) { return d, nil }, startPeer: func(context.Context) (peer, error) { d.calls = append(d.calls, "fixture-start"); return f, nil }, now: func() time.Time { return now }, pause: func(c context.Context, duration time.Duration) error {
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
				f.e.CollectionProfile = "basic-readonly-v1"
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
