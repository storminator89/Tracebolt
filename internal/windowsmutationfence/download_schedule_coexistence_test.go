package windowsmutationfence_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	wua "localrmm/internal/windowsupdatejob"
)

// The scheduled MSI permit fixes its original UTC bounds before the manual
// download starts. Both native edges below are inert adapters, not OS actions.
func TestDownloadCoexistenceBlocksScheduledMSIWithoutMovingWindow(t *testing.T) {
	for _, outcome := range []string{"active", "uncertain"} {
		t.Run(outcome, func(t *testing.T) {
			// MSI scheduling is independent; this fresh v8 WUA consent deliberately
			// does not opt into WUA installation scheduling.
			f := newPair(t, true, true, false, true, true, true, true)
			ctx := context.Background()
			initialConsent, initialGrant := objectDigest(f.consent), objectDigest(f.grant)
			if f.consent.Version != wua.DownloadCoexistenceConsentVersion || f.consent.ScheduleAcknowledged || f.consent.ScheduleScope != "" {
				t.Fatal("fixture silently enabled WUA scheduling")
			}
			msiPermit := scheduledMSIPermit(t, f)
			original, e := msi.VerifyPermit(msiPermit, public(f.msiKey))
			if e != nil {
				t.Fatal(e)
			}
			setDownloadReadiness(f)
			download := coexistenceDownloadPermit(t, f)
			if outcome == "uncertain" {
				f.wuaNative.closeError = wua.ErrUncertain
			}
			entered, release := make(chan struct{}), make(chan struct{})
			f.wuaNative.entered, f.wuaNative.release = entered, release
			type completion struct {
				result wua.Result
				err    error
			}
			done := make(chan completion, 1)
			go func() {
				r, err := f.executor.Execute(ctx, download)
				done <- completion{r, err}
			}()
			released := false
			t.Cleanup(func() {
				if !released {
					close(release)
					<-done
				}
			})
			await(t, entered)
			var finished completion
			if outcome == "uncertain" {
				close(release)
				released = true
				finished = <-done
				if finished.err != nil || finished.result.Outcome != "uncertain" || finished.result.CleanupSucceeded {
					t.Fatal("download lost cleanup uncertainty", finished)
				}
			}
			if st := f.fenceStatus(t); !st.Blocked || st.Domain != fence.CachedWUA {
				t.Fatal("download did not retain exact shared owner", st)
			}
			if e = f.endpoint.Accept(ctx, msiPermit); e != nil {
				t.Fatal(e)
			}
			f.endpoint.Wait()
			saved := readMSI(t, f.msiStore)
			report, e := msi.VerifyReport(saved.ResultReport, public(f.msiExecutorKey))
			if e != nil || report.State != "not_attempted" || saved.Attempted || f.msiNative.calls.Load() != 0 || !bytes.Equal(saved.InstallPermit, msiPermit) {
				t.Fatal("scheduled MSI crossed download owner or changed permit", e)
			}
			if outcome == "active" {
				close(release)
				released = true
				finished = <-done
				if finished.err != nil || finished.result.Outcome != "succeeded" {
					t.Fatal("settled download", finished)
				}
			}
			// Releasing a settled owner cannot replay a consumed blocked permit.
			if e = f.endpoint.Accept(ctx, msiPermit); !errors.Is(e, msi.ErrConsumed) {
				t.Fatal("blocked scheduled permit was rearmed inside original window", e)
			}
			// Closing the fixed window cannot move or refresh that permit either.
			f.at.Store(original.ScheduleEndAt)
			f.endpoint.Close()
			f.openMSI(t)
			if e = f.endpoint.Accept(ctx, msiPermit); e == nil {
				t.Fatal("closed window revived blocked scheduled installation")
			}
			after := readMSI(t, f.msiStore)
			p, e := msi.VerifyPermit(after.InstallPermit, public(f.msiKey))
			if e != nil || p != original || !bytes.Equal(after.ResultReport, saved.ResultReport) || f.msiNative.calls.Load() != 0 || f.wuaNative.calls.Load() != 1 || objectDigest(f.consent) != initialConsent || objectDigest(f.grant) != initialGrant {
				t.Fatal("coexistence shifted window, authority, result or attempt", e)
			}
			if outcome == "uncertain" && !f.fenceStatus(t).Blocked {
				t.Fatal("elapsed window unlocked uncertain download")
			}
		})
	}
}

func coexistenceDownloadPermit(t *testing.T, f *pairedDomains) []byte {
	t.Helper()
	ctx := context.Background()
	r, e := wua.NewRecordWithExecutor(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wua.EncodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	store := &reusableWUAHandshakeStore{raw: raw, f: f}
	m, e := wua.OpenTransactional(ctx, store, f.consent.Binding, f.wuaKey, f.now)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	actor, job, device := id("operator_", 10), id("update_", 6001), f.consent.Binding.DeviceID
	if e = m.ConfigureDownloadPolicy(func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	if e = m.RequestDownload(ctx, device, actor, job, f.wuaNative.readiness.Selection); e != nil {
		t.Fatal(e)
	}
	challenge, e := m.ClaimReadiness(ctx, job)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := f.executor.Readiness(ctx, challenge)
	if e != nil {
		t.Fatal(e)
	}
	status, e := f.executor.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Report(ctx, status.MutationReport); e != nil {
		t.Fatal(e)
	}
	if e = m.Report(ctx, proof); e != nil {
		t.Fatal(e)
	}
	view, e := m.View(ctx, device, actor)
	if e != nil || view.Job == nil || view.Job.Preview == nil {
		t.Fatal("download-only review", e)
	}
	if e = m.ApproveDownload(ctx, device, actor, job, view.Job.Preview.Digest, true); e != nil {
		t.Fatal(e)
	}
	permit, e := m.ClaimDownload(ctx, job)
	if e != nil {
		t.Fatal(e)
	}
	return permit
}
