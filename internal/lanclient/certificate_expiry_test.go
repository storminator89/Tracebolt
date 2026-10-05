package lanclient

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/model"
	"reflect"
	"strings"
	"testing"
)

func TestPackageObservationShapeRejectsOperatorCertificateMetadata(t *testing.T) {
	// Shape-only fixture. Runtime validity/signature/retry remains covered by
	// TestPackageSenderExactRetryAndSignature with its full ephemeral fixture.
	d := model.Device{ID: "sandbox-local", Tags: []string{}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	raw, err := json.Marshal(d)
	if err != nil || strings.Contains(string(raw), "agentCertificate") {
		t.Fatal("unchanged endpoint shape includes operator metadata")
	}
	check := func(raw []byte) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		return exactShape(decoder, reflect.TypeOf(model.Device{}), 0)
	}
	if check(raw) != nil {
		t.Fatal("unchanged package-frame shape rejected")
	}
	for _, value := range []string{`null`, `{}`, `{"source":"guided-enrollment","expiresAt":"2026-10-06T12:00:00Z","checkedAt":"2026-10-05T12:00:00Z"}`} {
		injected := strings.Replace(string(raw), `"id":"sandbox-local"`, `"agentCertificate":`+value+`,"id":"sandbox-local"`, 1)
		if injected == string(raw) || check([]byte(injected)) == nil {
			t.Fatal("operator metadata accepted in pending package frame")
		}
	}
}
