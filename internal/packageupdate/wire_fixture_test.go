package packageupdate

import (
	"bytes"
	"encoding/json"
	"flag"
	"localrmm/internal/actionpermit"
	"os"
	"testing"
	"time"
)

var updateWorkflowFixture = flag.Bool("update-package-update-fixtures", false, "write deterministic synthetic workflow contract fixture (never host data)")

func TestSharedWorkflowWireFixtures(t *testing.T) {
	r, req, p := fixture(t)
	views := map[string]View{"unavailable": unavailableView(r.Binding.DeviceID, time.Unix(at, 0).UTC()), "idle": projectView(r, time.Unix(at, 0).UTC())}
	save := func(name string, r Record, now int64) {
		t.Helper()
		if e := Validate(ctx, r); e != nil {
			t.Fatal(e)
		}
		views[name] = projectView(r, time.Unix(now, 0).UTC())
	}
	prepared, e := Prepare(ctx, r, req, actor, at)
	if e != nil {
		t.Fatal(e)
	}
	save(Preparing, prepared, at)
	failed, e := FailPreparation(ctx, prepared, req.RequestID, at+1)
	if e != nil {
		t.Fatal(e)
	}
	save(PreparationFailed, failed, at+1)
	reviewed, e := AttachPreview(ctx, prepared, p, at+1)
	if e != nil {
		t.Fatal(e)
	}
	save(PreviewReady, reviewed, at+1)
	revoked, e := Revoke(ctx, reviewed, at+2)
	if e != nil {
		t.Fatal(e)
	}
	save(Revoked, revoked, at+2)
	approved, e := Approve(ctx, reviewed, ApprovalRequest{p.RequestID, p.Digest}, actor, at+2)
	if e != nil {
		t.Fatal(e)
	}
	save(Approved, approved, at+2)
	expired, e := Observe(ctx, approved, at+60)
	if e != nil {
		t.Fatal(e)
	}
	save(Expired, expired, at+60)
	claimed, e := ClaimForFixture(ctx, approved, p.RequestID, p.Digest, at+3)
	if e != nil {
		t.Fatal(e)
	}
	save(DeliveryUnknown, claimed, at+3)
	op := operationFor(claimed.Jobs[0])
	unknown, e := ObserveResult(ctx, claimed, p.RequestID, p.Digest, unknownResult(op, 1, at+4), at+4)
	if e != nil {
		t.Fatal(e)
	}
	save(NeedsIntervention, unknown, at+4)
	latest := claimed
	for i, phase := range []string{Applying, Verifying, Succeeded} {
		now := at + int64(i) + 4
		res := simulationResult(op, uint64(i+1), phase, now, "success", "required")
		latest, e = ObserveResult(ctx, latest, p.RequestID, p.Digest, res, now)
		if e != nil {
			t.Fatal(e)
		}
		save(phase, latest, now)
	}

	native, nreq, np, key := nativeFixture(t)
	save("native_idle", native, at)
	authority := signedNative(t, native, nreq, nil, key, at)
	native, e = PrepareNative(ctx, native, nreq, actor, at, authority)
	if e != nil {
		t.Fatal(e)
	}
	save("native_preparing", native, at)
	native, e = ClaimPreparation(ctx, native, nreq.RequestID, actionpermit.Digest(authority), at+1)
	if e != nil {
		t.Fatal(e)
	}
	uncertain, e := MarkPreparationUncertain(ctx, native, nreq.RequestID, at+2)
	if e != nil {
		t.Fatal(e)
	}
	save("native_preparation_uncertain", uncertain, at+2)
	native, e = AttachPreview(ctx, native, np, at+2)
	if e != nil {
		t.Fatal(e)
	}
	save("native_preview_ready", native, at+2)
	stale := projectView(native, time.Unix(at+2, 0).UTC())
	stale.Available = false
	stale.Reason = "native_adapter_unavailable"
	views["native_unavailable_preview"] = stale
	authority = signedNative(t, native, nreq, &np, key, at+3)
	native, e = ApproveNative(ctx, native, ApprovalRequest{np.RequestID, np.Digest}, actor, at+3, authority)
	if e != nil {
		t.Fatal(e)
	}
	save("native_approved", native, at+3)
	native, e = ClaimExecution(ctx, native, np.RequestID, np.Digest, at+4)
	if e != nil {
		t.Fatal(e)
	}
	save("native_delivery_unknown", native, at+4)
	nop := operationFor(native.Jobs[0])
	for i, phase := range []string{Applying, Verifying, Succeeded} {
		now := at + int64(i) + 5
		result := simulationResult(nop, uint64(i+1), phase, now, "success", "required")
		result.Reboot.Source = "native"
		result.Reason = "native_running"
		if phase == Succeeded {
			result.Reason = "native_verified"
		}
		native, e = ObserveResult(ctx, native, np.RequestID, np.Digest, result, now)
		if e != nil {
			t.Fatal(e)
		}
		save("native_"+phase, native, now)
	}
	raw, e := json.MarshalIndent(views, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := "../../web/src/package-update-go-fixtures.json"
	if *updateWorkflowFixture {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	existing, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(existing, raw) {
		t.Fatal("Go/TypeScript workflow fixture drift; regenerate explicit synthetic fixture and rerun both readers")
	}
}
