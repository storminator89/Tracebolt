package windowsmanagedmsi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestWorklistOriginalStageCanonicalBytesAndDigests(t *testing.T) {
	for _, tc := range []struct{ kind, operation, sequence, readiness, digest string }{
		{"deliver", "deliver", "", "", "a53a6f2fab7173406790e461c421fb11854df1c0b0afd70fe1bf41f1f4eb1334"},
		{"review", "review-coordinated", "1", "", "90f6084e8cc77fde84741031b1c466b18c6efdcdf86a77094d47ee62c3d7493e"},
		{"approve", "approve", "1", "ready", "5f10605e700e8567449a1f0dd02b943673ff2be1c64e6a1fc916d734f491e4ea"},
	} {
		q := WorklistRequest{DeviceID: "device", Operation: tc.operation, ArtifactID: "artifact", ArtifactRetiredCount: "0", BindingDigest: "binding", TransferID: "transfer", JobSequence: tc.sequence, ReadinessDigest: tc.readiness, ExpiresAt: 1800000060}
		raw, _ := json.Marshal(q)
		expected := fmt.Sprintf(`{"deviceId":"device","operation":%q,"artifactId":"artifact","artifactRetiredCount":"0","bindingDigest":"binding","transferId":"transfer","jobSequence":%q,"readinessDigest":%q,"expiresAt":1800000060}`, tc.operation, tc.sequence, tc.readiness)
		if string(raw) != expected {
			t.Fatalf("%s canonical bytes changed: %s", tc.kind, raw)
		}
		ack := WorklistAcknowledgements{Acknowledged: true}
		if tc.kind == "review" {
			ack = WorklistAcknowledgements{PackageReviewAccepted: true, TermsAccepted: true, MaintenanceAcknowledged: true, SynchronousReviewAccepted: true}
		}
		b := WorklistBatch{ID: "batch", Kind: tc.kind, ActorID: "actor", SessionDigest: "session", SessionExpiresAt: 1800000600, CreatedAt: 1800000000, ExpiresAt: 1800000060, Acknowledgements: ack, Items: []WorklistBatchItem{{Request: q}}}
		if b.Digest() != "sha256:"+tc.digest {
			t.Fatal("old stage digest changed", tc.kind, b.Digest())
		}
	}
}

func TestWorklistRetirementOnlyResultDigest(t *testing.T) {
	q := WorklistRequest{DeviceID: "agent_" + strings.Repeat("1", 32), Operation: "retire", ArtifactID: Digest([]byte("artifact")), ArtifactRetiredCount: "0", BindingDigest: Digest([]byte("binding")), TransferID: "transfer_" + strings.Repeat("2", 32), JobSequence: "1", ExpiresAt: 1800000060, ResultDigest: Digest([]byte("result"))}
	if !q.Valid("retire") || !(WorklistAcknowledgements{Acknowledged: true}).Valid("retire") {
		t.Fatal("exact retirement rejected")
	}
	for _, mutate := range []func(*WorklistRequest){func(q *WorklistRequest) { q.ResultDigest = "" }, func(q *WorklistRequest) { q.ReadinessDigest = Digest([]byte("ready")) }, func(q *WorklistRequest) { q.JobSequence = "0" }, func(q *WorklistRequest) { q.JobSequence = "01" }, func(q *WorklistRequest) { q.Operation = "approve" }, func(q *WorklistRequest) { q.ArtifactRetiredCount = "00" }} {
		bad := q
		mutate(&bad)
		if bad.Valid("retire") {
			t.Fatal("invalid retirement accepted", bad)
		}
	}
	for _, kind := range []string{"deliver", "review", "approve"} {
		bad := q
		bad.Operation = kind
		bad.ResultDigest = Digest([]byte("extraneous"))
		switch kind {
		case "deliver":
			bad.JobSequence = ""
		case "review":
			bad.Operation = "review-coordinated"
		case "approve":
			bad.ReadinessDigest = Digest([]byte("ready"))
		}
		if bad.Valid(kind) {
			t.Fatal("result digest allowed on old stage", kind)
		}
	}
}
