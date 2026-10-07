package main

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/windowsacceptance/native"
	"strings"
	"testing"
)

func TestReadOnlyPrerequisitesRejectSourceAndEveryMutatingMode(t *testing.T) {
	old := compiledSource
	compiledSource = strings.Repeat("a", 40)
	defer func() { compiledSource = old }()
	for _, args := range [][]string{nil, {"--run-service"}, {"--internal-denial-probe"}, {"--approve-services"}, {"--read-only-prerequisites", "--expected-source=" + strings.Repeat("b", 40)}, {"--read-only-prerequisites", "--expected-source=" + compiledSource, "--approve-services"}} {
		called := false
		var out, err bytes.Buffer
		if run(context.Background(), args, &out, &err, func(context.Context) native.PrerequisiteObservation {
			called = true
			return native.PrerequisiteObservation{}
		}) != 2 || called || out.Len() != 0 {
			t.Fatal("unbound/mutating mode reached inspector")
		}
	}
}
func TestReadOnlyPolicyResultsCannotClaimNativeAcceptance(t *testing.T) {
	old := compiledSource
	compiledSource = strings.Repeat("a", 40)
	defer func() { compiledSource = old }()
	for _, p := range []native.PrerequisiteObservation{{Status: "supported", Check: "complete", Reason: "none"}, {Status: "blocked", Check: "ancestor-policy", Reason: "prerequisite-blocked"}, {Status: "unverified", Check: "platform", Reason: "unsupported-platform"}} {
		var out, stderr bytes.Buffer
		calls := 0
		code := run(context.Background(), []string{"--read-only-prerequisites", "--expected-source=" + compiledSource}, &out, &stderr, func(c context.Context) native.PrerequisiteObservation {
			calls++
			if _, ok := c.Deadline(); !ok {
				t.Fatal("unbounded inspection")
			}
			return p
		})
		var r report
		if code != 0 || calls != 1 || json.Unmarshal(out.Bytes(), &r) != nil || !r.ReadOnly || r.NativeServiceAcceptance || r.EffectiveServiceTokenAccessVerified || r.HostMutated || r.Status != p.Status || r.Source != compiledSource {
			t.Fatal("read-only result overclaims or rejects finite blocker")
		}
	}
}
func TestReadOnlyMalformedInspectorEvidenceIsWithheld(t *testing.T) {
	old := compiledSource
	compiledSource = strings.Repeat("a", 40)
	defer func() { compiledSource = old }()
	var out, stderr bytes.Buffer
	if run(context.Background(), []string{"--read-only-prerequisites", "--expected-source=" + compiledSource}, &out, &stderr, func(context.Context) native.PrerequisiteObservation {
		return native.PrerequisiteObservation{Status: "secret"}
	}) != 1 || out.Len() != 0 || strings.Contains(stderr.String(), "secret") {
		t.Fatal("invalid native report exposed")
	}
}
