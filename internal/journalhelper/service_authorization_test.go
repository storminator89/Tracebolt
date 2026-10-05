package journalhelper

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalview"
)

func allSystemServicesState() State {
	s := generationState()
	s.Policy.SchemaVersion = journalpolicy.VersionV3
	s.Policy.Scope = journalpolicy.ScopeV3
	s.Policy.ServiceAuthorization = journalpolicy.AllSystemServices
	s.Policy.AllowedUnits = []string{}
	s.PolicyGeneration, _ = journalpolicy.PolicyGeneration(s.Policy)
	return s
}

func TestV3HelperAllowsFutureExactServiceThroughExistingTBJ2Protocol(t *testing.T) {
	state := allSystemServicesState()
	if validateState(state, fixtureIdentity()) != nil {
		t.Fatal("valid v3 authority denied")
	}
	q := sampleRequest()
	q.Query.Unit = "newly-installed.service"
	q.PolicyGeneration = state.PolicyGeneration
	wire, err := EncodeRequest(q)
	if err != nil || string(wire[:4]) != "TBJ2" {
		t.Fatal("v3 policy changed exact-query helper protocol")
	}
	d := fixtureDependencies()
	d.Load = func() (State, error) { return state, nil }
	var calls atomic.Int32
	d.Capture = func(ctx context.Context, query journalview.Query, now time.Time) (journalview.Snapshot, error) {
		calls.Add(1)
		if query != q.Query {
			t.Fatal("helper expanded the exact query")
		}
		return journalview.CollectWithProvider(ctx, query, now, fixtureProvider{raw: `{"__REALTIME_TIMESTAMP":"1791115230000000","_SYSTEMD_UNIT":"newly-installed.service","PRIORITY":"4","MESSAGE":"synthetic safe message"}` + "\n"})
	}
	srv, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	result, err := exchange(t, srv, context.Background(), q)
	if err != nil || result.Status != StatusSnapshot || calls.Load() != 1 || result.PolicyDigest != state.PolicyGeneration.PolicyDigest {
		t.Fatal("broad authority failed exact new service capture", err, result.Status)
	}
	q.Operation, q.PolicyDigest, q.Revision = VerifyOperation, result.PolicyDigest, result.Revision
	result, err = exchange(t, srv, context.Background(), q)
	if err != nil || result.Status != StatusVerified || calls.Load() != 1 || len(result.Body()) != 0 {
		t.Fatal("v3 metadata verification recollected or failed")
	}
	for _, mutate := range []func(*State){
		func(s *State) { s.PolicyGeneration = journalgeneration.Tuple{} },
		func(s *State) { s.Deployment = fixtureState().Deployment },
		func(s *State) { s.PolicyGeneration.Generation = strings.Repeat("d", 64) },
		func(s *State) { s.Policy.SchemaVersion = journalpolicy.VersionV2 },
	} {
		bad := state
		mutate(&bad)
		if validateState(bad, fixtureIdentity()) == nil {
			t.Fatal("v3 authority bypassed deployment or generation binding")
		}
	}
}

func TestV3HelperDeniesLegacyRequestsAndScopeChangesBeforeRelease(t *testing.T) {
	state := allSystemServicesState()
	d := fixtureDependencies()
	d.Load = func() (State, error) { return state, nil }
	var calls atomic.Int32
	capture := d.Capture
	d.Capture = func(ctx context.Context, query journalview.Query, now time.Time) (journalview.Snapshot, error) {
		calls.Add(1)
		result, err := capture(ctx, query, now)
		state.Policy.ServiceAuthorization = journalpolicy.ExactUnits
		state.Policy.AllowedUnits = []string{"demo.service"}
		state.PolicyGeneration, _ = journalpolicy.PolicyGeneration(state.Policy)
		return result, err
	}
	srv, _ := New(d)
	q := sampleRequest()
	result, err := exchange(t, srv, context.Background(), q)
	if err != nil || result.Status != StatusDenied || calls.Load() != 0 {
		t.Fatal("legacy request reached broad grant capture")
	}
	q.PolicyGeneration = state.PolicyGeneration
	result, err = exchange(t, srv, context.Background(), q)
	if err != nil || result.Status != StatusDenied || calls.Load() != 1 || len(result.Body()) != 0 {
		t.Fatal("scope changed during capture but content escaped")
	}
}
