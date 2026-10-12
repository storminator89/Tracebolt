package windowssoftwareexecutor

import (
	"context"
	"errors"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	job "localrmm/internal/windowssoftwarejob"
)

type fakeNative struct {
	selection                             job.Selection
	prepared, verified, installed, closed int
	code                                  uint32
	present, busy                         bool
	registered                            job.Fact
	verifyErr                             error
	entered, release                      chan struct{}
}

func (f *fakeNative) prepare(_ context.Context, s job.Selection) error {
	f.prepared++
	if s != f.selection {
		return ErrIdentity
	}
	return nil
}
func (f *fakeNative) verify(context.Context) error { f.verified++; return f.verifyErr }
func (f *fakeNative) machineAbsent(context.Context, job.Selection) job.Fact {
	if f.present {
		return job.No
	}
	return job.Yes
}
func (f *fakeNative) installerBusy(context.Context) job.Fact {
	if f.busy {
		return job.Yes
	}
	return job.No
}
func (f *fakeNative) install(context.Context) (uint32, error) {
	f.installed++
	if f.entered != nil {
		close(f.entered)
		<-f.release
	}
	return f.code, nil
}
func (f *fakeNative) registration(context.Context, job.Selection) job.Fact { return f.registered }
func (f *fakeNative) verifyToken() error                                   { return nil }
func (f *fakeNative) close() error                                         { f.closed++; return nil }
func fakeSelection() job.Selection {
	return job.Selection{SHA256: actionpermit.Digest([]byte("fixture")), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Fixture package", TermsReviewDigest: actionpermit.Digest([]byte("terms")), ReviewReference: "Fixture"}
}
func TestFixedEngineRechecksCustodyRegistrationBusyAndFiniteGate(t *testing.T) {
	for _, kind := range []string{"success", "changed_custody", "new_registration", "busy", "expired_gate", "revoked_start"} {
		t.Run(kind, func(t *testing.T) {
			at := time.Unix(1800000000, 0)
			n := &fakeNative{selection: fakeSelection(), registered: job.Yes}
			e := &engine{native: n, selection: n.selection, now: func() time.Time { return at }, maintenanceUntil: at.Unix() + 60, checkStart: func(context.Context, time.Time) error { return nil }}
			if err := e.prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			r, err := e.inspect(context.Background())
			if err != nil || r.Reason() != "ready" {
				t.Fatal(r, err)
			}
			e.reviewed = &r
			switch kind {
			case "changed_custody":
				n.verifyErr = ErrIdentity
			case "new_registration":
				n.present = true
			case "busy":
				n.busy = true
			case "expired_gate":
				at = at.Add(time.Minute)
			case "revoked_start":
				e.checkStart = func(context.Context, time.Time) error { return job.ErrAuthority }
			}
			result, err := e.installOnce(context.Background())
			if kind == "success" {
				if err != nil || !result.ReturnCodeKnown || result.ReturnCode != 0 || result.RegistrationVerified != job.Yes || n.installed != 1 {
					t.Fatal(result, err)
				}
			} else if err == nil || n.installed != 0 || result.ReturnCodeKnown {
				t.Fatal("unsafe native call", result, err)
			}
			if _, err = e.installOnce(context.Background()); !errors.Is(err, ErrClosed) {
				t.Fatal("native retry", err)
			}
		})
	}
}
func TestPreparedOwnerRetainsCustodyThroughAbandonedNativeCall(t *testing.T) {
	n := &fakeNative{selection: fakeSelection(), registered: job.Yes, entered: make(chan struct{}), release: make(chan struct{})}
	a := newAdapter(func(context.Context) (nativeRuntime, error) { return n, nil }, time.Now)
	a.maintenanceUntil = time.Now().Add(time.Minute).Unix()
	a.checkStart = func(context.Context, time.Time) error { return nil }
	a.installLimit = time.Second
	p, err := a.PrepareExact(context.Background(), n.selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Inspect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.InstallOnce(ctx); done <- err }()
	<-n.entered
	cancel()
	if err = <-done; err == nil {
		t.Fatal("cancellation hidden")
	}
	if err = p.Close(); !errors.Is(err, ErrUncertain) {
		t.Fatal("unfinished native custody closed", err)
	}
	if n.closed != 0 {
		t.Fatal("pin released while installer running")
	}
	if _, err = a.PrepareExact(context.Background(), n.selection); !errors.Is(err, ErrClosed) {
		t.Fatal("replacement admitted", err)
	}
	close(n.release)
	<-p.(*prepared).done
	if n.closed != 1 || n.installed != 1 {
		t.Fatal("native owner cleanup")
	}
	if _, err = a.PrepareExact(context.Background(), n.selection); !errors.Is(err, ErrClosed) {
		t.Fatal("late completion revived admission", err)
	}
}
