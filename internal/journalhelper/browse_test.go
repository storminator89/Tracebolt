package journalhelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalview"
	"testing"
	"time"
)

func browseState() State {
	s := generationState()
	s.Policy.SchemaVersion = journalpolicy.VersionV4
	s.Policy.Scope = journalpolicy.ScopeV4
	s.Policy.BrowsingContract = journalview.BrowseContract
	s.Policy.ServiceAuthorization = journalpolicy.AllSystemServices
	s.Policy.AllowedUnits = []string{}
	s.Policy.MaxWindowSeconds = 0
	s.Policy.MaxLookbackSeconds = 0
	s.PolicyGeneration, _ = journalpolicy.PolicyGeneration(s.Policy)
	return s
}
func TestTBJ3CanonicalRoundtripAndDowngrade(t *testing.T) {
	r := generationRequest()
	r.PolicyGeneration = browseState().PolicyGeneration
	r.Query.BrowseMode = journalview.BrowseMode
	r.Query.Start = time.Unix(0, 0).UTC()
	r.Query.Search = "literal"
	r.Query.Cursor = "s=fixture;i=9"
	raw, e := EncodeRequest(r)
	if e != nil || string(raw[:4]) != "TBJ3" {
		t.Fatal("wrong helper contract", e)
	}
	got, e := readRequest(bytes.NewReader(raw))
	if e != nil || got != r {
		t.Fatal("roundtrip", e)
	}
	for _, magic := range []byte{'1', '2'} {
		bad := bytes.Clone(raw)
		bad[3] = magic
		if _, e := readRequest(bytes.NewReader(bad)); e == nil {
			t.Fatal("downgraded cursor request admitted")
		}
	}
	duplicate := append([]byte(`{"Operation":1,`), raw[9:]...)
	bad := append(bytes.Clone(raw[:8]), duplicate...)
	binary.BigEndian.PutUint32(bad[4:8], uint32(len(duplicate)))
	if _, e := readRequest(bytes.NewReader(bad)); e == nil {
		t.Fatal("duplicate query field admitted")
	}
}
func TestBrowseHelperPolicyRateAndVerify(t *testing.T) {
	state := browseState()
	d := fixtureDependencies()
	d.Load = func() (State, error) { return state, nil }
	now := d.Now()
	d.Now = func() time.Time { return now }
	calls := 0
	d.Capture = func(ctx context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		calls++
		return journalview.Parse(ctx, q, n, bytes.NewReader(nil))
	}
	s, _ := New(d)
	r := generationRequest()
	r.PolicyGeneration = state.PolicyGeneration
	r.Query.BrowseMode = journalview.BrowseMode
	r.Query.Start = time.Unix(0, 0).UTC()
	first, e := exchange(t, s, context.Background(), r)
	if e != nil || first.Status != StatusSnapshot || calls != 1 {
		t.Fatal("approved browse failed", e)
	}
	second, e := exchange(t, s, context.Background(), r)
	if e != nil || second.Status != StatusBusy || calls != 1 {
		t.Fatal("unbounded repeated helper reads")
	}
	verify := r
	verify.Operation = VerifyOperation
	verify.PolicyDigest = first.PolicyDigest
	verify.Revision = first.Revision
	if resp, e := exchange(t, s, context.Background(), verify); e != nil || resp.Status != StatusVerified || calls != 1 {
		t.Fatal("metadata verify read source")
	}
	now = now.Add(2 * time.Second)
	state.Policy.Enabled = false
	state.PolicyGeneration, _ = journalpolicy.PolicyGeneration(state.Policy)
	if resp, e := exchange(t, s, context.Background(), r); e != nil || resp.Status != StatusDenied || calls != 1 {
		t.Fatal("revoked policy read")
	}
}
