package enrollmentstore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"localrmm/internal/windowsupdatejob"
)

func TestWindowsUpdateSetupInspectionIsReadOnlyAndRefusesFencedDomain(t *testing.T) {
	for _, setup := range []bool{false, true} {
		f := newWindowsUpdateStoreFixture(t, setup)
		f.store.Close()
		before, e := os.ReadFile(f.path)
		if e != nil {
			t.Fatal(e)
		}
		got, e := InspectWindowsUpdateJobSetup(context.Background(), f.path, f.fixture.issuerDER, f.consent.Binding.DeviceID, f.at)
		if e != nil {
			t.Fatal(e)
		}
		want := "absent"
		if setup {
			want = "fenced"
		}
		if got.Status != want || got.Identity.Issuance.CertificateHash != f.snapshot.Issuance.CertificateHash || got.CurrentLeafDigest != "sha256:"+f.snapshot.Issuance.CertificateHash || got.CurrentLeafNotAfter != f.snapshot.Intent.NotAfter {
			t.Fatal("inspection binding", got)
		}
		expired := WithOverviewClock(context.Background(), func() time.Time { return time.Unix(f.snapshot.Intent.NotAfter, 0).UTC() })
		if _, e := InspectWindowsUpdateJobSetup(expired, f.path, f.fixture.issuerDER, f.consent.Binding.DeviceID, f.at); e == nil {
			t.Fatal("inspection used a stale pre-wait clock")
		}
		after, e := os.ReadFile(f.path)
		if e != nil || string(before) != string(after) {
			t.Fatal("read-only inspection wrote database")
		}
	}
}
func TestWindowsUpdateSetupExpectedCurrentLeafCannotBeSubstituted(t *testing.T) {
	for _, kind := range []string{"digest", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsUpdateStoreFixture(t, false)
			digest, expiry := f.consent.Binding.IncarnationDigest, f.snapshot.Intent.NotAfter
			if kind == "digest" {
				digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			} else {
				expiry++
			}
			ctx := WithWindowsUpdateSetupExpectedLeaf(context.Background(), digest, expiry)
			e := f.store.SetupWindowsUpdateJobsCreateOnly(ctx, f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), f.consent, f.at)
			if !errors.Is(e, windowsupdatejob.ErrAuthority) {
				t.Fatal("unreviewed leaf admitted", e)
			}
		})
	}
}
func TestWindowsUpdateSetupFinalInputGuardPrecedesLastExpiryCheck(t *testing.T) {
	f := newWindowsUpdateStoreFixture(t, false)
	at := f.at
	ctx := windowsupdatejob.WithFinalCheck(WithOverviewClock(context.Background(), func() time.Time { return at }), func() error { at = time.Unix(f.snapshot.Intent.NotAfter, 0).UTC(); return nil })
	if e := f.store.SetupWindowsUpdateJobsCreateOnly(ctx, f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), f.consent, f.at); e == nil {
		t.Fatal("expired during final protected-file guard")
	}
	if e := f.store.OpenWindowsUpdateJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); !errors.Is(e, windowsupdatejob.ErrUnavailable) {
		t.Fatal("rejected setup committed domain", e)
	}
}
