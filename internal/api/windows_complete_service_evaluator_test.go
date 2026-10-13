package api

import (
	"bytes"
	"context"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
	"testing"
	"time"
)

func TestCompleteServiceHealthRecorderEvaluatorGuards(t *testing.T) {
	for _, mode := range []string{"generation", "grant", "revoked", "final-clock"} {
		t.Run(mode, func(t *testing.T) {
			h, f, op, _ := completeHealthHandlerFixture(t)
			path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete/policy"
			if w := completeServiceRequest(h, op, "POST", path, completeServiceBody(f)); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			start := f.now
			for i := 0; i < 4; i++ {
				f.now = start.Add(time.Duration(i) * 30 * time.Second)
				if e := h.app.windowsCapacity.evaluate(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			before, e := h.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
			if e != nil {
				t.Fatal(e)
			}
			rawBefore, _ := windowsservicehealth.Encode(before)
			f.now = start.Add(120 * time.Second)
			p := &f.sampleComplete.Source
			p.Sequence++
			p.CapturedAt = f.now
			p.CaptureFinishedAt = f.now
			p.ReceivedAt = f.now
			p.ExpiresAt = f.now.Add(24 * time.Hour)
			p.GenerationID, _ = windowsfullservices.GenerationID(f.inputs[0].DeviceID, p.GrantID, p.Sequence)
			f.onGuard = func(n int) {
				if n != 5 {
					return
				}
				switch mode {
				case "generation":
					f.sampleComplete.Source.ManifestSHA256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
				case "grant":
					f.sampleComplete.Source.GrantRevision++
				case "revoked":
					f.inputs[0].Authorized = false
				case "final-clock":
					f.now = f.inputs[0].AuthorityUntil
				}
			}
			if e := h.app.windowsCapacity.evaluate(context.Background()); e == nil {
				t.Fatal("evaluator admitted changed final authority", mode)
			}
			after, e := h.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
			rawAfter, _ := windowsservicehealth.Encode(after)
			if e != nil || !bytes.Equal(rawBefore, rawAfter) || h.app.windowsCapacity.epoch != "" {
				t.Fatal("failed commit changed source state or retained epoch", e)
			}
		})
	}
	// Persistently revoked enabled state can only become unknown; it must not
	// repeatedly poison the coordinated evaluator's ready/epoch state.
	h, f, op, _ := completeHealthHandlerFixture(t)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete/policy"
	if w := completeServiceRequest(h, op, "POST", path, completeServiceBody(f)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	f.inputs[0].Authorized = false
	for i := 0; i < 2; i++ {
		if e := h.app.windowsCapacity.evaluate(context.Background()); e != nil || !h.app.windowsCapacity.ready {
			t.Fatal("revoked policy blocks coordinated monitoring", e)
		}
	}
	state, e := h.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
	if e != nil || state.Checks[0].Status != "unknown" || len(state.Incidents) != 0 {
		t.Fatal(e, state)
	}
}
