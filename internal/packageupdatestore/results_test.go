//go:build linux

package packageupdatestore

import (
	"encoding/json"
	"errors"
	"testing"

	"localrmm/internal/packageupdate"
)

func resultFor(r packageupdate.Record, phase string, at int64) packageupdate.Result {
	j := r.Jobs[len(r.Jobs)-1]
	out := packageupdate.Result{Sequence: uint64(len(j.Results) + 1), Phase: phase, ObservedAt: at, Packages: []packageupdate.PackageResult{}, Reboot: packageupdate.RebootEvidence{State: "unknown", Source: "simulation", ObservedAt: at}, DpkgState: "unknown", Reason: "simulated_running"}
	for _, p := range j.Preview.Plan.Packages {
		item := packageupdate.PackageResult{Name: p.Name, Architecture: p.Architecture, ExpectedVersion: p.To.Version, Outcome: "unknown"}
		if phase == packageupdate.Succeeded {
			v := p.To.Version
			item.ObservedVersion = &v
			item.Outcome = "verified"
		}
		out.Packages = append(out.Packages, item)
	}
	if phase == packageupdate.Succeeded {
		out.Reason = "simulated_verified"
		out.DpkgState = "clean"
		out.Reboot.State = "required"
	}
	if phase == packageupdate.NeedsIntervention {
		out.Reason = "runner_state_unknown"
	}
	return out
}
func TestResultsAndRebootEvidenceSurviveCleanRestart(t *testing.T) {
	s, path, r, p := approved(t)
	next, err := packageupdate.ClaimForFixture(ctx, r, p.RequestID, p.Digest, now+3)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	r = next
	for i, phase := range []string{packageupdate.Applying, packageupdate.Verifying, packageupdate.Succeeded} {
		result := resultFor(r, phase, now+int64(i)+4)
		next, err = packageupdate.ObserveResult(ctx, r, p.RequestID, p.Digest, result, result.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		save(t, s, r, next)
		r = next
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err = OpenExisting(ctx, path, r.Binding)
		if err != nil {
			t.Fatal(err)
		}
		assertRecord(t, s, r)
	}
	defer s.Close()
	if r.Jobs[0].Results[2].Reboot.State != "required" {
		t.Fatal("lost bounded reboot observation")
	}
	// Exact retries keep the original source, capture times, package versions and
	// reboot observation. Later delivery cannot fabricate a refreshed observation.
	result := r.Jobs[0].Results[2]
	next, err = packageupdate.ObserveResult(ctx, r, p.RequestID, p.Digest, result, now+1000)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	r = next
	changed := clone(t, r)
	changed.Revision++
	changed.ClockFloor++
	changed.Jobs[0].Results[0].Reboot.State = "not_reported"
	if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, encodeWithoutValidation(t, changed)); err == nil {
		t.Fatal("rewrote prior result evidence")
	}
	changed = clone(t, r)
	changed.Revision++
	changed.ClockFloor++
	changed.Jobs[0].Results[2].Reboot.State = "not_reported"
	if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, changed)); !errors.Is(err, packageupdate.ErrConflict) {
		t.Fatal("rewrote completed reboot evidence", err)
	}
	changed = clone(t, r)
	changed.Revision++
	changed.ClockFloor++
	changed.Jobs[0].Results = changed.Jobs[0].Results[:2]
	changed.Jobs[0].State = packageupdate.Verifying
	if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, changed)); !errors.Is(err, packageupdate.ErrConflict) {
		t.Fatal("removed result history", err)
	}
	assertRecord(t, s, r)
	// Only genuinely completed history permits another preparation, retaining the
	// entire prior job; no pruning, new incarnation or counter reset is involved.
	req := r.Jobs[0].Request
	req.RequestID = "update_22222222222222222222222222222222"
	next, err = packageupdate.Prepare(ctx, r, req, actor, r.ClockFloor)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	if len(next.Jobs) != 2 || next.Jobs[1].Sequence != 2 {
		t.Fatal("lost sequence floor")
	}
}
func TestClaimUnknownAndInterventionCannotResetOnReopen(t *testing.T) {
	for _, intervene := range []bool{false, true} {
		t.Run(map[bool]string{false: "delivery-unknown", true: "intervention"}[intervene], func(t *testing.T) {
			s, path, r, p := approved(t)
			next, err := packageupdate.ClaimForFixture(ctx, r, p.RequestID, p.Digest, now+3)
			if err != nil {
				t.Fatal(err)
			}
			save(t, s, r, next)
			r = next
			if intervene {
				result := resultFor(r, packageupdate.NeedsIntervention, now+4)
				next, err = packageupdate.ObserveResult(ctx, r, p.RequestID, p.Digest, result, now+4)
				if err != nil {
					t.Fatal(err)
				}
				save(t, s, r, next)
				r = next
			}
			next, err = packageupdate.Revoke(ctx, r, now+1000)
			if err != nil {
				t.Fatal(err)
			}
			save(t, s, r, next)
			r = next
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenExisting(ctx, path, r.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			assertRecord(t, s, r)
			if r.Jobs[0].ClaimedAt != now+3 || (r.Jobs[0].State != packageupdate.DeliveryUnknown && r.Jobs[0].State != packageupdate.NeedsIntervention) {
				t.Fatal("invented cancellation or clean result")
			}
			next, err = packageupdate.ClaimForFixture(ctx, r, p.RequestID, p.Digest, now+1001)
			if err != nil {
				t.Fatal(err)
			}
			save(t, s, r, next)
			if next.Jobs[0].ClaimedAt != now+3 {
				t.Fatal("renewed claim")
			}
		})
	}
}

func encodeWithoutValidation(t *testing.T, r packageupdate.Record) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
