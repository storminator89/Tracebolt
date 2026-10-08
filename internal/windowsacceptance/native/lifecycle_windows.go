//go:build windows

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/windows"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

const operationBound = 45 * time.Second

type retainedReceipt struct {
	Version  int                    `json:"version"`
	Service  windowsservice.Receipt `json:"service"`
	Prepared bool                   `json:"prepared"`
}

func (s *nativeState) captureRoot(path string) error {
	h, id, err := openChecked(path, true, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return ErrAcceptance
	}
	windows.CloseHandle(h)
	s.objects = append(s.objects, ownedObject{path: path, id: id, directory: true})
	return nil
}
func approved(ctx context.Context, g Guard) bool {
	return ctx != nil && ctx.Err() == nil && g != nil && g.Check()
}
func (d *Driver) prepare(ctx context.Context, g Guard, raw []byte) error {
	s, ok := d.native()
	if !ok || !d.evidence.Provisioned || d.receipt.InstallationID != "" {
		return d.fail(ReasonState)
	}
	b, err := enrollmentclient.ParseBootstrap(raw)
	if err != nil || b.Profile != d.options.Selection.Transport || b.CollectionProfile != d.options.Selection.CollectionProfile {
		return d.fail(ReasonState)
	}
	p, err := windowsservice.Plan(ctx)
	if err != nil || p.Existing.Exists || p.Layout != s.layout || p.ExecutableSHA256 != d.options.ServiceSHA256 {
		return d.fail(ReasonOwnership)
	}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	journal, err := windowsstate.Open(s.layout.StateRoot+"-installer", windowsagentconfig.Installer(true))
	if err != nil {
		return d.fail(ReasonState)
	}
	defer journal.Close()
	if s.captureRoot(s.layout.StateRoot+"-installer") != nil {
		return d.fail(ReasonOwnership)
	}
	intent, err := json.Marshal(p)
	if err != nil || !approved(ctx, g) || journal.Write("intent.json", intent) != nil {
		return d.fail(ReasonState)
	}
	d.evidence.Stage = StageInstall
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	d.receipt, err = windowsservice.ApplyInstall(ctx, p)
	retained := retainedReceipt{Version: 1, Service: d.receipt}
	saved, encodeErr := json.Marshal(retained)
	if encodeErr != nil || !approved(ctx, g) || journal.Write("receipt.json", saved) != nil {
		return d.fail(ReasonState)
	}
	if err != nil || !d.receipt.Complete {
		return d.fail(ReasonOperation)
	}
	d.evidence.Installed = true
	d.evidence.Stopped = true
	d.evidence.Stage = StagePrepare
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	root, err := windowsstate.Open(s.layout.StateRoot, windowsagentconfig.RuntimeRoot(d.receipt.ServiceSID, true))
	if err != nil {
		return d.fail(ReasonState)
	}
	defer root.Close()
	if s.captureRoot(s.layout.StateRoot) != nil {
		return d.fail(ReasonOwnership)
	}
	if !approved(ctx, g) || root.Write("bootstrap.json", raw) != nil {
		return d.fail(ReasonState)
	}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	enrollment, err := root.CreateDirectoryStore("enrollment", windowsagentconfig.Enrollment(d.receipt.ServiceSID, true))
	if err != nil {
		return d.fail(ReasonState)
	}
	if enrollment.Close() != nil || root.Close() != nil {
		return d.fail(ReasonState)
	}
	retained.Prepared = true
	saved, err = json.Marshal(retained)
	if err != nil || !approved(ctx, g) || journal.Write("receipt.json", saved) != nil || journal.Close() != nil {
		return d.fail(ReasonState)
	}
	d.bootstrap = b
	d.evidence.Prepared = true
	return nil
}
func (d *Driver) requireStopped(ctx context.Context) bool {
	if !d.receipt.Complete {
		return false
	}
	snap, err := windowsservice.InspectOwned(ctx, d.receipt)
	return err == nil && snap.State == windowsservice.Stopped
}
func (d *Driver) verifyReceipt() bool {
	s, ok := d.native()
	if !ok || !d.receipt.Complete {
		return false
	}
	store, err := windowsstate.Open(s.layout.StateRoot+"-installer", windowsagentconfig.Installer(false))
	if err != nil {
		return false
	}
	defer store.Close()
	raw, err := store.Read("receipt.json")
	if err != nil {
		return false
	}
	defer clear(raw)
	want, err := json.Marshal(retainedReceipt{Version: 1, Service: d.receipt, Prepared: d.evidence.Prepared})
	return err == nil && bytes.Equal(raw, want)
}
func (d *Driver) claim(ctx context.Context, g Guard, secret func(context.Context) ([]byte, error), display func(enrollmentclient.TrustDisplay) error) error {
	s, ok := d.native()
	if !ok || !d.evidence.Prepared || d.evidence.ClaimCommitted || secret == nil || display == nil || !d.verifyReceipt() || !d.requireStopped(ctx) {
		return d.fail(ReasonState)
	}
	result, err := enrollmentclient.Run(ctx, d.bootstrap, enrollmentclient.Options{StateDirectory: s.layout.EnrollmentRoot, ClaimOnly: true, WindowsInventoryAcknowledged: d.options.Selection.Inventory(), InsecureHTTPAcknowledged: d.options.Selection.HTTPTest(),
		Display: func(t enrollmentclient.TrustDisplay) error {
			if !approved(ctx, g) {
				return ErrAcceptance
			}
			return display(t)
		},
		Secret: func(c context.Context) ([]byte, error) {
			if !approved(c, g) {
				return nil, ErrAcceptance
			}
			return secret(c)
		},
	})
	if err != nil || !result.Pending || result.ServerAuthenticated == d.options.Selection.HTTPTest() {
		return d.fail(ReasonOperation)
	}
	if _, err = enrollmentclient.InspectService(d.bootstrap, s.layout.EnrollmentRoot, d.options.Selection.HTTPTest()); err != nil {
		return d.fail(ReasonState)
	}
	binding, err := d.claimIdentity()
	if err != nil {
		return d.fail(ReasonState)
	}
	s.claimBinding = binding
	d.evidence.ClaimCommitted = true
	return nil
}
func (d *Driver) claimIdentity() ([32]byte, error) {
	var zero [32]byte
	s, ok := d.native()
	if !ok {
		return zero, ErrAcceptance
	}
	st, err := windowsstate.Open(s.layout.EnrollmentRoot, windowsagentconfig.Enrollment(d.receipt.ServiceSID, false))
	if err != nil {
		return zero, ErrAcceptance
	}
	defer st.Close()
	marker, err := st.Read("service-enrollment.json")
	if err != nil {
		return zero, ErrAcceptance
	}
	defer clear(marker)
	// Immutable committed identity fields only; state/revision legitimately move.
	var m struct {
		ClaimID        string `json:"claimId"`
		ClaimRequestID string `json:"claimRequestId"`
		KeyFingerprint string `json:"keyFingerprint"`
		CSRHash        string `json:"csrHash"`
		ClaimHash      string `json:"claimHash"`
		ClaimAt        int64  `json:"claimAt"`
		DeadlineAt     int64  `json:"deadlineAt"`
	}
	if json.Unmarshal(marker, &m) != nil || m.ClaimID == "" || m.ClaimRequestID == "" || m.KeyFingerprint == "" || m.ClaimAt <= 0 || m.DeadlineAt <= m.ClaimAt {
		return zero, ErrAcceptance
	}
	bound, err := json.Marshal(m)
	if err != nil {
		return zero, ErrAcceptance
	}
	defer clear(bound)
	return sha256.Sum256(bound), nil
}
func wait(ctx context.Context) error {
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ErrAcceptance
	case <-timer.C:
		return nil
	}
}
func (d *Driver) awaitState(ctx context.Context, want windowsservice.State) error {
	return d.awaitStateForCleanup(ctx, want, false)
}
func (d *Driver) awaitStateForCleanup(ctx context.Context, want windowsservice.State, cleanupOnly bool) error {
	c, cancel := context.WithTimeout(ctx, operationBound)
	defer cancel()
	for {
		snapshot, err := windowsservice.InspectOwned(c, d.receipt)
		if err != nil {
			return d.fail(ReasonOwnership)
		}
		arrived, rejected := transitionObservation(snapshot, want, cleanupOnly)
		if rejected {
			return d.fail(ReasonOperation)
		}
		if arrived {
			d.evidence.Running = want == windowsservice.Running
			d.evidence.Stopped = want == windowsservice.Stopped
			return nil
		}
		if wait(c) != nil {
			return d.fail(ReasonTimeout)
		}
	}
}
func (d *Driver) start(ctx context.Context, g Guard) error {
	if !d.evidence.ClaimCommitted || !d.verifyReceipt() || !approved(ctx, g) {
		return d.fail(ReasonState)
	}
	if _, err := windowsservice.ApplyStart(ctx, d.receipt); err != nil {
		return d.fail(ReasonOperation)
	}
	return d.awaitState(ctx, windowsservice.Running)
}
func (d *Driver) status(ctx context.Context) error {
	if !d.receipt.Complete {
		return d.fail(ReasonState)
	}
	s, err := windowsservice.InspectOwned(ctx, d.receipt)
	if err != nil {
		return d.fail(ReasonOwnership)
	}
	d.evidence.Running = s.State == windowsservice.Running
	d.evidence.Stopped = s.State == windowsservice.Stopped
	return nil
}
func (d *Driver) inspectToken(ctx context.Context) error {
	if !d.receipt.Complete {
		return d.fail(ReasonState)
	}
	s, err := windowsservice.InspectOwned(ctx, d.receipt)
	if err != nil || s.State != windowsservice.Running || s.ProcessID == 0 || !validateProcessToken(s.ProcessID, d.receipt.ServiceSID, "") {
		return d.fail(ReasonOwnership)
	}
	// Recheck PID after token inspection to reject a service transition/PID race.
	again, err := windowsservice.InspectOwned(ctx, d.receipt)
	if err != nil || again.State != windowsservice.Running || again.ProcessID != s.ProcessID {
		return d.fail(ReasonOwnership)
	}
	d.evidence.LimitedToken = true
	return nil
}
func (d *Driver) stop(ctx context.Context, g Guard) error {
	if !d.verifyReceipt() || !approved(ctx, g) {
		return d.fail(ReasonOwnership)
	}
	if _, err := windowsservice.ApplyStop(ctx, d.receipt); err != nil {
		return d.fail(ReasonOperation)
	}
	return d.awaitState(ctx, windowsservice.Stopped)
}
func (d *Driver) cleanupStop(ctx context.Context, g Guard) error {
	if !d.verifyReceipt() || !approved(ctx, g) {
		return d.fail(ReasonOwnership)
	}
	if _, err := windowsservice.ApplyStop(ctx, d.receipt); err != nil {
		return d.fail(ReasonOperation)
	}
	return d.awaitStateForCleanup(ctx, windowsservice.Stopped, true)
}
func (d *Driver) stateContinuity(ctx context.Context) error {
	s, ok := d.native()
	if !ok || !d.evidence.ClaimCommitted || !d.verifyReceipt() || !d.requireStopped(ctx) {
		return d.fail(ReasonState)
	}
	bound, err := d.claimIdentity()
	if err != nil || bound != s.claimBinding {
		return d.fail(ReasonOwnership)
	}
	state, err := enrollmentclient.InspectService(d.bootstrap, s.layout.EnrollmentRoot, d.options.Selection.HTTPTest())
	if err != nil {
		return d.fail(ReasonState)
	}
	d.evidence.IdentityRetained = true
	d.evidence.Ready = state.Ready
	if !state.Ready {
		return nil
	}
	sender, err := windowsstate.Open(s.layout.SenderRoot, windowsagentconfig.Sender(d.receipt.ServiceSID, false))
	if err != nil {
		return d.fail(ReasonState)
	}
	defer sender.Close()
	raw, err := sender.Read("state.json")
	if err != nil {
		return d.fail(ReasonState)
	}
	defer clear(raw)
	next, present, retained, err := observeSender(s.sender, raw)
	if err != nil {
		return d.fail(ReasonOwnership)
	}
	s.sender = next
	d.evidence.PendingPresent = present
	if retained {
		d.evidence.PendingBytesRetained = true
	}
	d.evidence.SenderFloorRetained = true
	return nil
}
func (d *Driver) uninstall(ctx context.Context, g Guard) error {
	if !d.verifyReceipt() || !d.requireStopped(ctx) || !approved(ctx, g) {
		return d.fail(ReasonOwnership)
	}
	before, err := d.snapshotRetainedState()
	if err != nil {
		return d.fail(ReasonOwnership)
	}
	if _, err := windowsservice.ApplyUninstall(ctx, d.receipt); err != nil {
		return d.fail(ReasonOperation)
	}
	c, cancel := context.WithTimeout(ctx, operationBound)
	defer cancel()
	for {
		snap, err := windowsservice.Inspect(c)
		if err == nil && !snap.Exists {
			d.evidence.Uninstalled = true
			d.evidence.Installed = false
			after, err := d.snapshotRetainedState()
			if err != nil || !reflect.DeepEqual(before, after) {
				return d.fail(ReasonOwnership)
			}
			d.evidence.UninstallStateRetained = true
			return nil
		}
		if err == nil && snap.Exists && snap.Configuration.Description == "" {
			return d.fail(ReasonOwnership)
		}
		if wait(c) != nil {
			return d.fail(ReasonTimeout)
		}
	}
}

func (d *Driver) protectedObjectsExist() bool {
	s, ok := d.native()
	if !ok || !s.sender.seen || !d.evidence.Ready {
		return false
	}
	// Opening the exact protected stores proves these names are initialized; a
	// probe's ERROR_ACCESS_DENIED alone would not establish existence.
	for _, v := range []struct {
		root, name string
		options    windowsstate.Options
	}{{s.layout.EnrollmentRoot, "agent-key.pem", windowsagentconfig.Enrollment(d.receipt.ServiceSID, false)}, {filepath.Join(s.layout.EnrollmentRoot, "telemetry"), "state.json", windowsagentconfig.Sender(d.receipt.ServiceSID, false)}} {
		st, err := windowsstate.Open(v.root, v.options)
		if err != nil {
			return false
		}
		raw, err := st.Read(v.name)
		clear(raw)
		closeErr := st.Close()
		if err != nil || closeErr != nil {
			return false
		}
	}
	return true
}
