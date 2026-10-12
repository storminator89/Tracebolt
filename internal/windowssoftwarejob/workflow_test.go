package windowssoftwarejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/windowsupdatejob"
)

func TestExactPackageUncheckedApprovalAndDomainSeparation(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	v, e := f.m.View(ctx, f.consent.Binding.DeviceID, f.actor)
	if e != nil || v.Package != f.consent.Package {
		t.Fatal("missing prepared package", e)
	}
	changed := f.consent.Package
	changed.SHA256 = actionpermit.Digest([]byte("other"))
	if e = f.m.Request(ctx, f.consent.Binding.DeviceID, f.actor, f.id, changed); !errors.Is(e, ErrAuthority) {
		t.Fatal("different package granted", e)
	}
	f.request(t)
	p := f.m.record.Jobs[0].Preview
	if e = f.m.Approve(ctx, f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, false); e == nil {
		t.Fatal("unchecked approval")
	}
	raw := f.approve(t)
	if _, e = windowsupdatejob.Verify(raw, f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("MSI became WUA authority")
	}
	if _, e = Verify(append(raw, '\n'), f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("noncanonical permit")
	}
	tampered := bytes.Replace(raw, []byte("Reviewed package"), []byte("Another package"), 1)
	if _, e = Verify(tampered, f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("tampered package")
	}
	if e = f.m.Request(ctx, f.consent.Binding.DeviceID, f.actor, "software_"+strings.Repeat("9", 32), f.consent.Package); e == nil {
		t.Fatal("second lifetime operation")
	}
}
func TestNumericOutcomesAndVerifiedRegistration(t *testing.T) {
	for _, tc := range []struct {
		code       uint32
		registered Fact
		want       string
	}{{0, Yes, "succeeded"}, {0, No, "uncertain"}, {0, Unknown, "uncertain"}, {3010, Yes, "restart_required"}, {3010, No, "restart_required"}, {1641, Unknown, "unexpected_restart"}, {1618, No, "busy"}, {1603, Unknown, "failed"}} {
		t.Run(tc.want+string(tc.registered), func(t *testing.T) {
			f := fixture(t)
			raw := f.approve(t)
			n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: tc.code, ReturnCodeKnown: true, RegistrationVerified: tc.registered}}
			x, s := executorFixture(t, f, n)
			n.onInstall = func() {
				var r ExecutorRecord
				if canonical(s.files["executor.json"], &r, MaxBytes) != nil || !r.Attempts[0].Attempted || r.Attempts[0].Result != nil {
					t.Fatal("native before durable attempt")
				}
			}
			got, e := x.Execute(context.Background(), raw)
			if e != nil || got.Outcome != tc.want || got.ReturnCode != tc.code || got.RegistrationVerified != tc.registered || n.installs != 1 {
				t.Fatal(got, e)
			}
			x = reopenExecutor(t, f, s, n)
			if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
				t.Fatal("native replay", e)
			}
			proof, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw))
			if e != nil {
				t.Fatal(e)
			}
			statement, e := VerifyStatement(proof, executorKey().Public().(ed25519.PublicKey))
			if e != nil || statement.Result.ReturnCode != tc.code {
				t.Fatal("numeric evidence lost", e)
			}
		})
	}
}
func TestOneSignedReadinessThenExactEvidence(t *testing.T) {
	f := fixture(t)
	raw := requestChallenge(t, f)
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}
	x, s := executorFixture(t, f, n)
	proof, e := x.Readiness(context.Background(), raw)
	if e != nil || n.installs != 0 {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), proof); e != nil {
		t.Fatal(e)
	}
	p := f.m.record.Jobs[0].Preview
	if e = f.m.Review(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id); e != nil {
		t.Fatal(e)
	}
	if e = f.m.Approve(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	x = reopenExecutor(t, f, s, n)
	retry, e := x.Outbox(context.Background(), "readiness", f.id, actionpermit.Digest(raw))
	if e != nil || !bytes.Equal(retry, proof) {
		t.Fatal("changed original evidence")
	}
	if _, e = x.Readiness(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.opens != 1 {
		t.Fatal("readiness replay", e)
	}
	permit, e := f.m.Claim(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.m.Claim(context.Background(), f.id); !errors.Is(e, ErrConsumed) {
		t.Fatal("redelivered", e)
	}
	if _, e = x.Execute(context.Background(), permit); e != nil {
		t.Fatal(e)
	}
	result, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(permit))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), result); e != nil {
		t.Fatal(e)
	}
	f.at = f.at.Add(5 * time.Minute)
	f.guard.current.LeafNotAfter += 600
	if e = f.m.Report(context.Background(), result); e != nil {
		t.Fatal("identical saved report replay rejected", e)
	}
}
func TestCustodyAndReviewFactsFailClosed(t *testing.T) {
	for name, change := range map[string]func(*Readiness){"hash": func(r *Readiness) { r.PackageVerified = No }, "installed": func(r *Readiness) { r.MachineAbsent = No }, "busy": func(r *Readiness) { r.InstallerBusy = Yes }, "review": func(r *Readiness) { r.PackageReviewAccepted = No }, "acceptance": func(r *Readiness) { r.NativeAcceptance = Unknown }, "expired_gate": func(r *Readiness) { r.MaintenanceWindowEnd = r.CapturedAt }} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			change(&f.source.value)
			f.request(t)
			if f.m.record.Jobs[0].State != "blocked" {
				t.Fatal("unready package approved")
			}
		})
	}
	f := fixture(t)
	f.source.value.MaintenanceWindowEnd = f.at.Unix() + 5
	f.request(t)
	if f.m.record.Jobs[0].Preview.ExpiresAt != f.at.Unix()+5 {
		t.Fatal("gate extended")
	}
}
func TestUncertainDurabilityNeverCallsOrReplays(t *testing.T) {
	for _, commit := range []bool{false, true} {
		f := fixture(t)
		raw := f.approve(t)
		n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}
		x, s := executorFixture(t, f, n)
		s.fail = 2
		s.commitFailure = commit
		if _, e := x.Execute(context.Background(), raw); !errors.Is(e, ErrUncertain) || n.installs != 0 {
			t.Fatal("attempt after uncertain write", e)
		}
		s.fail = 0
		if _, e := x.Execute(context.Background(), raw); e == nil || n.installs != 0 {
			t.Fatal("uncertain session replay", e)
		}
		x = reopenExecutor(t, f, s, n)
		if _, e := x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 0 {
			t.Fatal("uncertain restart replay", e)
		}
	}
}
