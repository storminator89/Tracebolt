package api

import (
	"context"
	"encoding/json"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedMSIWorklistRetirementStrictOptionalBatch(t *testing.T) {
	ref := msi.WorklistDispatchReference{WorklistID: "worklist_" + strings.Repeat("a", 32), BatchID: "batch_" + strings.Repeat("b", 32), Item: 0}
	batch, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	artifact, binding, result := msi.Digest([]byte("reviewed artifact")), msi.Digest([]byte("original binding")), msi.Digest([]byte("exact signed result"))
	transfer := "transfer_" + strings.Repeat("c", 32)
	legacy := `{"artifactId":"` + artifact + `","bindingDigest":"` + binding + `","resultDigest":"` + result + `","acknowledged":true}`
	reusable := strings.TrimSuffix(legacy, "}") + `,"artifactRetiredCount":"0","transferId":"` + transfer + `","jobSequence":"1"}`
	withBatch := strings.TrimSuffix(reusable, "}") + `,"batch":` + string(batch) + `}`
	for _, test := range []struct {
		name, body     string
		reusable, want bool
	}{
		{"legacy unchanged", legacy, false, true},
		{"per-device reusable unchanged", reusable, true, true},
		{"exact optional batch", withBatch, true, true},
		{"legacy batch forbidden", strings.TrimSuffix(legacy, "}") + `,"batch":` + string(batch) + `}`, false, false},
		{"legacy occurrence not promoted", reusable, false, false},
		{"missing result", strings.Replace(withBatch, `"resultDigest":"`+result+`",`, "", 1), true, false},
		{"duplicate result", strings.Replace(withBatch, `"resultDigest":`, `"resultDigest":"`+result+`","resultDigest":`, 1), true, false},
		{"null result", strings.Replace(withBatch, `"resultDigest":"`+result+`"`, `"resultDigest":null`, 1), true, false},
		{"missing occurrence", strings.Replace(withBatch, `"artifactRetiredCount":"0",`, "", 1), true, false},
		{"number occurrence", strings.Replace(withBatch, `"artifactRetiredCount":"0"`, `"artifactRetiredCount":0`, 1), true, false},
		{"missing transfer", strings.Replace(withBatch, `"transferId":"`+transfer+`",`, "", 1), true, false},
		{"missing job", strings.Replace(withBatch, `"jobSequence":"1",`, "", 1), true, false},
		{"number job", strings.Replace(withBatch, `"jobSequence":"1"`, `"jobSequence":1`, 1), true, false},
		{"unknown outer", strings.TrimSuffix(withBatch, "}") + `,"retry":true}`, true, false},
		{"readiness is not result", strings.Replace(withBatch, `"resultDigest":`, `"readinessDigest":`, 1), true, false},
		{"null batch", strings.Replace(withBatch, string(batch), "null", 1), true, false},
		{"duplicate batch", strings.TrimSuffix(withBatch, "}") + `,"batch":` + string(batch) + `}`, true, false},
		{"duplicate nested", strings.Replace(withBatch, `"item":0`, `"item":0,"item":0`, 1), true, false},
		{"unknown nested", strings.Replace(withBatch, `"item":0`, `"item":0,"resume":true`, 1), true, false},
		{"missing nested item", strings.Replace(withBatch, `,"item":0`, "", 1), true, false},
		{"noncanonical nested order", strings.Replace(withBatch, string(batch), `{"batchId":"`+ref.BatchID+`","worklistId":"`+ref.WorklistID+`","item":0}`, 1), true, false},
		{"negative item", strings.Replace(withBatch, `"item":0`, `"item":-1`, 1), true, false},
		{"item beyond bound", strings.Replace(withBatch, `"item":0`, `"item":25`, 1), true, false},
		{"fractional item", strings.Replace(withBatch, `"item":0`, `"item":0.0`, 1), true, false},
		{"string item", strings.Replace(withBatch, `"item":0`, `"item":"0"`, 1), true, false},
		{"trailing object", withBatch + `{}`, true, false},
		{"bounded body", strings.Repeat(" ", 1280) + withBatch, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var in struct {
				Batch                *msi.WorklistDispatchReference `json:"batch,omitempty"`
				ArtifactRetiredCount string                         `json:"artifactRetiredCount,omitempty"`
				TransferID           string                         `json:"transferId,omitempty"`
				JobSequence          string                         `json:"jobSequence,omitempty"`
				ArtifactID           string                         `json:"artifactId"`
				BindingDigest        string                         `json:"bindingDigest"`
				ResultDigest         string                         `json:"resultDigest"`
				Acknowledged         bool                           `json:"acknowledged"`
			}
			fields := []string{"artifactId", "bindingDigest", "resultDigest", "acknowledged"}
			if test.reusable {
				fields = append(fields, "artifactRetiredCount", "transferId", "jobSequence")
			}
			r := httptest.NewRequest("POST", "https://manager.test/api/devices/agent_"+strings.Repeat("d", 32)+"/windows-managed-msi/retire", strings.NewReader(test.body))
			w := httptest.NewRecorder()
			if got := readManagedMSIBatchObject(w, r, test.reusable, fields, &in); got != test.want {
				t.Fatalf("accepted %v, want %v; HTTP %d", got, test.want, w.Code)
			}
			if !test.want {
				if w.Code < 400 || w.Code >= 500 {
					t.Fatalf("invalid request did not fail closed: HTTP %d", w.Code)
				}
				return
			}
			if in.ArtifactID != artifact || in.BindingDigest != binding || in.ResultDigest != result || !in.Acknowledged {
				t.Fatal("strict parser changed exact retirement references")
			}
			if test.reusable && (in.ArtifactRetiredCount != "0" || in.TransferID != transfer || in.JobSequence != "1") {
				t.Fatal("strict parser lost reusable job occurrence")
			}
			if test.name == "exact optional batch" && (in.Batch == nil || *in.Batch != ref) {
				t.Fatal("strict parser lost exact batch reference")
			}
		})
	}
}

func TestManagedMSIWorklistRetirementBatchContextCannotDowngrade(t *testing.T) {
	h := &operatorHandler{}
	r := httptest.NewRequest("POST", "https://manager.test/api/devices/agent_"+strings.Repeat("d", 32)+"/windows-managed-msi/retire", nil)
	ref := &msi.WorklistDispatchReference{WorklistID: "worklist_" + strings.Repeat("a", 32), BatchID: "batch_" + strings.Repeat("b", 32), Item: 0}
	q := msi.WorklistRequest{Operation: "retire", ResultDigest: msi.Digest([]byte("exact signed result"))}
	ack := msi.WorklistAcknowledgements{Acknowledged: true}
	if _, err := h.managedMSIBatchContext(r, ref, q, ack); !errors.Is(err, msi.ErrAuthority) {
		t.Fatal("missing registry downgraded retirement batch to ordinary request", err)
	}
	// An unchanged per-device request preserves the caller's final session guard.
	called := false
	guarded := msi.WithFinalCheck(context.Background(), func() error { called = true; return msi.ErrAuthority })
	r = r.WithContext(guarded)
	ctx, err := h.managedMSIBatchContext(r, nil, q, ack)
	if err != nil || ctx != guarded {
		t.Fatal("legacy retirement context changed", err)
	}
	if err = msi.CheckFinal(ctx); !errors.Is(err, msi.ErrAuthority) || !called {
		t.Fatal("per-device retirement lost final session fence", err)
	}
}
