package windowsmutationfence_test

import (
	"bytes"
	"context"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

func scheduledMSIPermit(t *testing.T, f *pairedDomains) []byte {
	t.Helper()
	ctx := context.Background()
	p, e := msi.VerifyPermit(f.msiPermit, public(f.msiKey))
	if e != nil {
		t.Fatal(e)
	}
	f.at.Add(60)
	p.Kind = "readiness"
	p.ReadinessDigest = ""
	p.Sequence++
	p.IssuedAt = f.at.Load()
	p.ExpiresAt = p.IssuedAt + 60
	p.MaintenanceUntil = p.IssuedAt + 120
	p.ScheduleDigest = digest("exact prospective approval")
	p.ScheduleStartAt = p.IssuedAt
	p.ScheduleEndAt = p.MaintenanceUntil
	raw, e := msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, raw); e != nil {
		t.Fatal("scheduled inspection", e)
	}
	st, e := f.endpoint.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p.Kind = "install"
	p.ReadinessDigest = msi.Digest(st.Report)
	raw, e = msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestScheduledMSIEndpointOneAttemptAndNativeEdge(t *testing.T) {
	for _, change := range []string{"none", "expiry", "local_revocation", "leaf"} {
		t.Run(change, func(t *testing.T) {
			f := newPair(t, true, true, false, true)
			ctx := context.Background()
			raw := scheduledMSIPermit(t, f)
			p, _ := msi.VerifyPermit(raw, public(f.msiKey))
			f.msiNative.beforeStart = func() {
				switch change {
				case "expiry":
					f.at.Store(p.ExpiresAt)
				case "local_revocation":
					f.msiCurrent.Revoked = true
				case "leaf":
					f.msiCurrent.LeafDigest = digest("changed leaf")
				}
			}
			if e := f.endpoint.Accept(ctx, raw); e != nil {
				t.Fatal(e)
			}
			// Poll the inert asynchronous adapter only; never a Windows/native install.
			deadline := time.Now().Add(3 * time.Second)
			var result []byte
			for time.Now().Before(deadline) {
				data, _ := f.msiStore.Read("endpoint.json")
				var r msi.EndpointRecord
				if msi.Canonical(data, &r, msi.MaxRecordBytes) == nil && len(r.ResultReport) > 0 {
					result = r.ResultReport
					break
				}
				time.Sleep(time.Millisecond)
			}
			if len(result) == 0 {
				t.Fatal("inert result missing")
			}
			report, e := msi.VerifyReport(result, public(f.msiExecutorKey))
			if e != nil {
				t.Fatal(e)
			}
			if change == "none" {
				if f.msiNative.calls.Load() != 1 || report.Result.Outcome != "succeeded" {
					t.Fatal("one native admission")
				}
				f.endpoint.Close()
				f.openMSI(t)
				st, e := f.endpoint.Status(ctx)
				if e != nil || !bytes.Equal(st.Report, result) {
					t.Fatal("restart result", e)
				}
				if e = f.endpoint.Accept(ctx, raw); e == nil {
					t.Fatal("restart native replay")
				}
			} else if f.msiNative.calls.Load() != 0 || report.Result.Outcome != "uncertain" {
				t.Fatal("final local authority bypass")
			}
		})
	}
}
