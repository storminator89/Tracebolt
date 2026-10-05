package journalhelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalview"
)

func generationState() State {
	s := fixtureState()
	s.Policy.SchemaVersion = journalpolicy.VersionV2
	s.Policy.Revision = 1
	s.Policy.Generation = strings.Repeat("b", 64)
	s.Deployment.SchemaVersion = DeploymentVersionV2
	s.Deployment.PolicyGenerationRequired = true
	s.PolicyGeneration, _ = journalpolicy.PolicyGeneration(s.Policy)
	return s
}
func generationRequest() Request {
	r := sampleRequest()
	r.PolicyGeneration = generationState().PolicyGeneration
	return r
}
func TestTBJ2ExactBinaryRoundTripAndLegacyFrameUnchanged(t *testing.T) {
	legacy, _ := EncodeRequest(sampleRequest())
	if string(legacy[:4]) != "TBJ1" || len(legacy) != 124+len(sampleRequest().Query.Unit) {
		t.Fatal("legacy frame changed")
	}
	for _, revision := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		query := generationRequest()
		query.PolicyGeneration.Revision = revision
		verify := query
		verify.Operation = VerifyOperation
		verify.PolicyDigest = query.PolicyGeneration.PolicyDigest
		verify.Revision = "sha256:" + strings.Repeat("c", 64)
		for _, r := range []Request{query, verify} {
			b, err := EncodeRequest(r)
			if err != nil {
				t.Fatal(err)
			}
			if string(b[:4]) != "TBJ2" || len(b) != len(legacy)+generationFrameBytes || len(b) > MaxRequestBytes {
				t.Fatal("wrong v2 frame")
			}
			got, err := readRequest(bytes.NewReader(b))
			if err != nil || got != r {
				t.Fatal("v2 frame roundtrip", err)
			}
			clear(b)
			if got != r {
				t.Fatal("frame aliases input")
			}
		}
	}
}
func TestTBJ2MalformedTupleLengthVersionAndOperationsReject(t *testing.T) {
	r := generationRequest()
	raw, _ := EncodeRequest(r)
	offset := len(raw) - generationFrameBytes
	tests := map[string]func([]byte) []byte{
		"downgrade":       func(b []byte) []byte { b[3] = '1'; return b },
		"unknown-version": func(b []byte) []byte { b[3] = '3'; return b },
		"zero-revision":   func(b []byte) []byte { clear(b[offset : offset+8]); return b },
		"zero-generation": func(b []byte) []byte { clear(b[offset+8 : offset+40]); return b },
		"zero-digest":     func(b []byte) []byte { clear(b[offset+40:]); return b },
		"truncated":       func(b []byte) []byte { return b[:len(b)-1] },
		"missing-tuple":   func(b []byte) []byte { b = b[:offset]; binary.BigEndian.PutUint32(b[4:8], uint32(len(b)-8)); return b },
		"duplicate-tuple": func(b []byte) []byte {
			b = append(b, b[offset:]...)
			binary.BigEndian.PutUint32(b[4:8], uint32(len(b)-8))
			return b
		},
		"oversize":          func(b []byte) []byte { binary.BigEndian.PutUint32(b[4:8], ^uint32(0)); return b },
		"generic-command":   func(b []byte) []byte { b[8] = 3; return b },
		"query-digest-slot": func(b []byte) []byte { b[41] = 1; return b },
		"unit-length":       func(b []byte) []byte { binary.BigEndian.PutUint16(b[105:107], 65535); return b },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := readRequest(bytes.NewReader(mutate(bytes.Clone(raw)))); err == nil {
				t.Fatal("malformed v2 accepted")
			}
		})
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.PolicyGeneration.Revision = 0 }, func(r *Request) { r.PolicyGeneration.Generation = strings.Repeat("B", 64) }, func(r *Request) { r.PolicyGeneration.PolicyDigest = "" }, func(r *Request) { r.Query.Unit = "kernel" }, func(r *Request) { r.Query.Unit = "" }, func(r *Request) {
		r.Operation = VerifyOperation
		r.PolicyDigest = "sha256:" + strings.Repeat("f", 64)
		r.Revision = "sha256:" + strings.Repeat("a", 64)
	}} {
		bad := r
		mutate(&bad)
		if _, err := EncodeRequest(bad); err == nil {
			t.Fatal("invalid v2 encoded")
		}
	}
	// A v1 frame relabeled as v2 cannot manufacture the missing exact tuple.
	legacy, _ := EncodeRequest(sampleRequest())
	legacy[3] = '2'
	if _, err := readRequest(bytes.NewReader(legacy)); err == nil {
		t.Fatal("v1 promoted without tuple")
	}
}
func TestV2AuthorityRequiresMigratedDeploymentAndCommittedExactTuple(t *testing.T) {
	state := generationState()
	if validateState(state, fixtureIdentity()) != nil {
		t.Fatal("valid v2 authority denied")
	}
	raw, _ := json.Marshal(state.Deployment)
	got, err := decodeDeployment(raw)
	if err != nil || got != state.Deployment {
		t.Fatal("v2 deployment roundtrip")
	}
	for name, mutate := range map[string]func(*State){
		"missing-activation":     func(s *State) { s.PolicyGeneration = journalgeneration.Tuple{} },
		"old-activation":         func(s *State) { s.PolicyGeneration.Revision++ },
		"same-revision-conflict": func(s *State) { s.PolicyGeneration.Generation = strings.Repeat("c", 64) },
		"policy-digest-conflict": func(s *State) { s.PolicyGeneration.PolicyDigest = "sha256:" + strings.Repeat("d", 64) },
		"unmigrated-deployment":  func(s *State) { s.Deployment = fixtureState().Deployment },
		"false-migrated-bit":     func(s *State) { s.Deployment.PolicyGenerationRequired = false },
		"downgraded-policy":      func(s *State) { s.Policy = fixtureState().Policy; s.PolicyGeneration = journalgeneration.Tuple{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := state
			mutate(&bad)
			if validateState(bad, fixtureIdentity()) == nil {
				t.Fatal("inconsistent authority accepted")
			}
		})
	}
	legacy := fixtureState()
	legacy.PolicyGeneration = state.PolicyGeneration
	if validateState(legacy, fixtureIdentity()) == nil {
		t.Fatal("v2 activation accepted with legacy policy")
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"policyGenerationRequired":true`), []byte(`"policyGenerationRequired":false`), 1), bytes.Replace(raw, []byte(`,"policyGenerationRequired":true`), nil, 1), bytes.Replace(raw, []byte(DeploymentVersionV2), []byte(DeploymentVersion), 1), append([]byte(`{"policyGenerationRequired":true,`), raw[1:]...)} {
		if _, err := decodeDeployment(bad); err == nil {
			t.Fatal("ambiguous deployment accepted")
		}
	}
}
func TestV2HelperBindsCaptureAndMetadataVerification(t *testing.T) {
	state := generationState()
	d := fixtureDependencies()
	d.Load = func() (State, error) { return state, nil }
	var calls atomic.Int32
	capture := d.Capture
	d.Capture = func(c context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		calls.Add(1)
		return capture(c, q, n)
	}
	server, _ := New(d)
	q := generationRequest()
	result, err := exchange(t, server, context.Background(), q)
	if err != nil || result.Status != StatusSnapshot || result.PolicyDigest != q.PolicyGeneration.PolicyDigest || calls.Load() != 1 {
		t.Fatal("bound capture failed", err, result.Status)
	}
	q.Operation = VerifyOperation
	q.PolicyDigest = result.PolicyDigest
	q.Revision = result.Revision
	result, err = exchange(t, server, context.Background(), q)
	if err != nil || result.Status != StatusVerified || calls.Load() != 1 || len(result.Body()) != 0 {
		t.Fatal("bound metadata verify failed")
	}
}
func TestV2HelperDeniesPredecessorLegacyAndConflictingRequestsBeforeCapture(t *testing.T) {
	for name, mutate := range map[string]func(*State, *Request){
		"legacy-queued": func(s *State, r *Request) { r.PolicyGeneration = journalgeneration.Tuple{} },
		"old-revision": func(s *State, r *Request) {
			s.Policy.Revision++
			s.Policy.Generation = strings.Repeat("c", 64)
			s.PolicyGeneration, _ = journalpolicy.PolicyGeneration(s.Policy)
		},
		"same-revision-conflict":        func(s *State, r *Request) { r.PolicyGeneration.Generation = strings.Repeat("d", 64) },
		"same-revision-policy-conflict": func(s *State, r *Request) { r.PolicyGeneration.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
		"policy-downgrade":              func(s *State, r *Request) { *s = fixtureState() },
		"missing-activation":            func(s *State, r *Request) { s.PolicyGeneration = journalgeneration.Tuple{} },
		"new-unit-not-allowed":          func(s *State, r *Request) { r.Query.Unit = "other.service" },
	} {
		t.Run(name, func(t *testing.T) {
			state := generationState()
			q := generationRequest()
			mutate(&state, &q)
			d := fixtureDependencies()
			d.Load = func() (State, error) { return state, nil }
			var calls atomic.Int32
			d.Capture = func(context.Context, journalview.Query, time.Time) (journalview.Snapshot, error) {
				calls.Add(1)
				return journalview.Snapshot{}, nil
			}
			s, _ := New(d)
			r, err := exchange(t, s, context.Background(), q)
			if err != nil || r.Status != StatusDenied || calls.Load() != 0 {
				t.Fatal("unsafe request reached capture", err, r.Status)
			}
		})
	}
}
func TestV2HelperFinalReleaseDeniesGenerationChange(t *testing.T) {
	for _, change := range []func(*State){func(s *State) {
		s.Policy.Revision++
		s.Policy.Generation = strings.Repeat("c", 64)
		s.PolicyGeneration, _ = journalpolicy.PolicyGeneration(s.Policy)
	}, func(s *State) { s.PolicyGeneration = journalgeneration.Tuple{} }, func(s *State) { *s = fixtureState() }} {
		state := generationState()
		d := fixtureDependencies()
		d.Load = func() (State, error) { return state, nil }
		capture := d.Capture
		d.Capture = func(c context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
			result, err := capture(c, q, n)
			change(&state)
			return result, err
		}
		s, _ := New(d)
		r, err := exchange(t, s, context.Background(), generationRequest())
		if err != nil || r.Status != StatusDenied || len(r.Body()) != 0 {
			t.Fatal("unsent content released under changed generation", err)
		}
	}
}
