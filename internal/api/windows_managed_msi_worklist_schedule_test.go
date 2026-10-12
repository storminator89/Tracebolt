package api

import (
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFleetScheduledMSIStrictOptionalBatchAndPreviewRoute(t *testing.T) {
	q := msi.ScheduleRequest{ArtifactID: msi.Digest([]byte("artifact")), ArtifactRetiredCount: 4, BindingDigest: msi.Digest([]byte("binding")), TransferID: "transfer_" + strings.Repeat("a", 32), JobSequence: 9, ReadinessDigest: msi.Digest([]byte("ready")), StartAt: 2000000000, EndAt: 2000000060, PackageReviewAccepted: true, TermsAccepted: true, ServiceRiskAccepted: true, SynchronousActionsAccepted: true, ScheduleAccepted: true}
	raw, _ := json.Marshal(q)
	ref := msi.WorklistDispatchReference{WorklistID: "worklist_" + strings.Repeat("b", 32), BatchID: "batch_" + strings.Repeat("c", 32), Item: 0}
	batch, _ := json.Marshal(ref)
	body := strings.TrimSuffix(string(raw), "}") + `,"batch":` + string(batch) + `}`
	fields := []string{"artifactId", "artifactRetiredCount", "bindingDigest", "transferId", "jobSequence", "readinessDigest", "startAt", "endAt", "packageReviewAccepted", "termsAccepted", "serviceRiskAccepted", "synchronousActionsAccepted", "scheduleAccepted"}
	for name, wire := range map[string]string{"standalone": string(raw), "original-body-ceiling": strings.Repeat(" ", 1800) + string(raw), "too-large": strings.Repeat(" ", 4096) + string(raw), "batch": body, "null-batch": strings.Replace(body, string(batch), "null", 1), "duplicate-window": strings.TrimSuffix(body, "}") + `,"startAt":2000000000}`, "missing-ack": strings.Replace(body, `,"scheduleAccepted":true`, "", 1), "unknown": strings.TrimSuffix(body, "}") + `,"retry":true}`, "noncanonical-reference": strings.Replace(body, `"item":0`, `"item":0.0`, 1)} {
		t.Run(name, func(t *testing.T) {
			var in struct {
				msi.ScheduleRequest
				Batch *msi.WorklistDispatchReference `json:"batch,omitempty"`
			}
			request := httptest.NewRequest("POST", "https://manager.invalid/", strings.NewReader(wire))
			ok := readManagedMSIBatchObjectBounded(httptest.NewRecorder(), request, true, fields, &in, 4096)
			if ok != (name == "standalone" || name == "original-body-ceiling" || name == "batch") {
				t.Fatal("strict body", ok)
			}
			if ok && (in.ScheduleRequest != q || name == "batch" && (in.Batch == nil || *in.Batch != ref)) {
				t.Fatal("lost exact original schedule")
			}
		})
	}
	request := httptest.NewRequest("POST", "https://manager.invalid/api/windows-managed-msi/worklists/"+ref.WorklistID+"/schedule-preview", nil)
	if id, op, ok := windowsMSIWorklistRoute(request); !ok || id != ref.WorklistID || op != "schedule-preview" {
		t.Fatal("preview route")
	}
}
