package windowsmanagedmsiexecutor

import (
	"context"
	"errors"
	managed "localrmm/internal/windowsmanagedmsi"
	"testing"
)

type packageFixture struct {
	ready    managed.Readiness
	result   managed.NativeResult
	closeErr error
	calls    int
}

func (p *packageFixture) Inspect(context.Context) (managed.Readiness, error) { return p.ready, nil }
func (p *packageFixture) InstallOnce(context.Context) (managed.NativeResult, error) {
	p.calls++
	return p.result, nil
}
func (p *packageFixture) Close() error { return p.closeErr }
func TestManagedCustodyCloseFailureSuppressesReady(t *testing.T) {
	p := &packageFixture{closeErr: errors.New("fixture close failure")}
	r, e := inspectPrepared(context.Background(), p)
	if e == nil || r != (managed.Readiness{}) {
		t.Fatal("cleanup failure became readiness")
	}
}
func TestManagedCustodyCloseFailureKeepsInstallUncertain(t *testing.T) {
	closeErr := errors.New("fixture close failure")
	selection := managed.Selection{SHA256: managed.Digest([]byte("fixture")), Size: 512, ProductCode: "{11111111-1111-1111-1111-111111111111}", PackageCode: "{22222222-2222-2222-2222-222222222222}", Version: "1.2.3", Architecture: "amd64", Name: "fixture", TermsReviewDigest: managed.Digest([]byte("terms")), ReviewReference: "fixture"}
	ready := managed.Readiness{Selection: selection, CapturedAt: 1700000000, PackageVerified: managed.Yes, MachineAbsent: managed.Yes, InstallerBusy: managed.No, NativeAcceptance: managed.Yes, PackageReviewAccepted: managed.Yes, MaintenanceWindowEnd: 1700000600}
	p := &packageFixture{ready: ready, result: managed.NativeResult{ReturnCodeKnown: true, ReturnCode: 0, RegistrationVerified: managed.Yes}, closeErr: closeErr}
	result, e := installPrepared(context.Background(), p, ready)
	if !errors.Is(e, closeErr) || p.calls != 1 || !result.ReturnCodeKnown || result.ReturnCode != 0 {
		t.Fatal("successful native code with failed custody cleanup was not uncertain", result, e, p.calls)
	}
}
