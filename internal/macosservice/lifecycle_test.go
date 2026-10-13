package macosservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type lifecycleFake struct {
	snapshot   InstallSnapshot
	events     []string
	opens      int
	reads      int
	failBefore string
	failAfter  string
	onRead     func(*lifecycleFake)
	closeError bool
}

func newLifecycleFake(profile string) *lifecycleFake {
	raw, _ := json.Marshal(basicFixture())
	if profile == InventoryProfile {
		raw, _ = json.MarshalIndent(inventoryFixture(), "", "  ")
	}
	return &lifecycleFake{snapshot: InstallSnapshot{PrerequisitesVerified: true, Config: raw, EnrollmentAnchorSHA256: strings.Repeat("c", 64), Custody: Absent, Plist: Absent, Job: Absent, Override: Absent}}
}
func (f *lifecycleFake) Open(context.Context, Request, bool) (InstallSession, error) {
	f.opens++
	return f, nil
}
func (f *lifecycleFake) Inspect(context.Context) (InstallSnapshot, error) {
	f.reads++
	if f.onRead != nil {
		f.onRead(f)
	}
	s := f.snapshot
	s.Config = append([]byte{}, s.Config...)
	s.Receipts = append([]Receipt{}, s.Receipts...)
	if s.Owner != nil {
		o := *s.Owner
		s.Owner = &o
	}
	return s, nil
}
func (f *lifecycleFake) effect(name string, fn func()) error {
	f.events = append(f.events, name)
	if f.failBefore == name {
		return errors.New("injected before")
	}
	fn()
	if f.failAfter == name {
		return errors.New("injected after")
	}
	return nil
}
func (f *lifecycleFake) Claim(_ context.Context, o Ownership) error {
	return f.effect("claim", func() { f.snapshot.Custody = Present; f.snapshot.Owner = &o })
}
func (f *lifecycleFake) AppendReceipt(_ context.Context, r Receipt) error {
	return f.effect(fmt.Sprint("receipt-", r.Sequence), func() { f.snapshot.Receipts = append(f.snapshot.Receipts, r) })
}
func (f *lifecycleFake) Publish(_ context.Context, o Ownership, plist string) error {
	return f.effect("publish", func() { f.snapshot.Plist = Present; f.snapshot.PlistSHA256 = digest([]byte(plist)) })
}
func (f *lifecycleFake) Bootstrap(_ context.Context, o Ownership) error {
	return f.effect("bootstrap", func() { f.snapshot.Job = Present; f.snapshot.JobOwnershipSHA256 = o.SHA256() })
}
func (f *lifecycleFake) Close() error {
	if f.closeError {
		return errors.New("close failed")
	}
	return nil
}
func installFixture(profile string, apply bool) InstallRequest {
	r := fixtureRequest()
	r.Profile = profile
	return InstallRequest{r, apply}
}

func TestCreateOnlyLifecycleHappyPathAndReadOnlyRecheck(t *testing.T) {
	for _, profile := range []string{BasicProfile, InventoryProfile} {
		t.Run(profile, func(t *testing.T) {
			f := newLifecycleFake(profile)
			p, e := Install(context.Background(), installFixture(profile, false), f)
			if e != nil || !p.ReadOnly || p.Status != "preflight-passed" || p.MutationAttempted || len(f.events) != 0 {
				t.Fatalf("preflight: %+v %v", p, e)
			}
			p, e = Install(context.Background(), installFixture(profile, true), f)
			want := []string{"claim", "receipt-1", "publish", "receipt-2", "receipt-3", "bootstrap", "receipt-4"}
			if e != nil || p.Status != "registration-confirmed" || !p.MutationAttempted || p.NativeAcceptanceVerified || !reflect.DeepEqual(f.events, want) || len(f.snapshot.Receipts) != 4 {
				t.Fatalf("apply: %+v %v %v", p, e, f.events)
			}
			f.events = nil
			for _, apply := range []bool{false, true} {
				p, e = Install(context.Background(), installFixture(profile, apply), f)
				if e != nil || p.Status != "registration-confirmed" || !p.ReadOnly || p.MutationAttempted || len(f.events) != 0 {
					t.Fatal("repeat mutated")
				}
			}
		})
	}
}
func TestUnavailableAndInvalidRequestsNeverInspect(t *testing.T) {
	r := installFixture(BasicProfile, true)
	p, e := Install(context.Background(), r, nil)
	if e != ErrUnavailable || p.AdapterAvailable || p.MutationAttempted || p.Status != "unavailable" {
		t.Fatal("native unavailable")
	}
	f := newLifecycleFake(BasicProfile)
	for _, change := range []func(*InstallRequest){func(r *InstallRequest) { r.Selection.RenderOnly = true }, func(r *InstallRequest) { r.Selection.Profile = "expanded" }, func(r *InstallRequest) { r.Selection.ServiceIdentity = "0:0" }} {
		bad := r
		change(&bad)
		if _, e = Install(context.Background(), bad, f); e != ErrRequest || f.opens != 0 {
			t.Fatal("invalid inspected")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = Install(ctx, r, f); e == nil || f.opens != 0 {
		t.Fatal("cancelled inspected")
	}
}
func TestFreshCollisionsAndMissingEvidenceBlockAllWrites(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*InstallSnapshot)
	}{
		{"unknown-job", func(s *InstallSnapshot) { s.Job = "" }},
		{"foreign-job", func(s *InstallSnapshot) { s.Job = Present }},
		{"existing-plist", func(s *InstallSnapshot) { s.Plist = Present }},
		{"disabled-override", func(s *InstallSnapshot) { s.Override = Present }},
		{"unknown-override", func(s *InstallSnapshot) { s.Override = "" }},
		{"uncertain-custody", func(s *InstallSnapshot) { s.Custody = "" }},
		{"partial-custody", func(s *InstallSnapshot) { s.Custody = Present }},
		{"orphan-receipt", func(s *InstallSnapshot) { s.Receipts = []Receipt{{Sequence: 1}} }},
		{"unknown-prerequisites", func(s *InstallSnapshot) { s.PrerequisitesVerified = false }},
		{"bad-enrollment-anchor", func(s *InstallSnapshot) { s.EnrollmentAnchorSHA256 = "" }},
		{"scope-substitution", func(s *InstallSnapshot) { s.Config, _ = json.MarshalIndent(inventoryFixture(), "", "  ") }},
		{"absent-job-with-evidence", func(s *InstallSnapshot) { s.JobOwnershipSHA256 = strings.Repeat("f", 64) }},
		{"absent-plist-with-evidence", func(s *InstallSnapshot) { s.PlistSHA256 = strings.Repeat("f", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLifecycleFake(BasicProfile)
			test.change(&f.snapshot)
			p, e := Install(context.Background(), installFixture(BasicProfile, true), f)
			if e == nil || p.MutationAttempted || len(f.events) > 0 {
				t.Fatalf("collision mutated: %v", e)
			}
		})
	}
}
func TestEveryUncertainWriteStopsAndNeverReplays(t *testing.T) {
	order := []string{"claim", "receipt-1", "publish", "receipt-2", "receipt-3", "bootstrap", "receipt-4"}
	for i, event := range order {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-after-%v", event, after), func(t *testing.T) {
				f := newLifecycleFake(BasicProfile)
				if after {
					f.failAfter = event
				} else {
					f.failBefore = event
				}
				p, e := Install(context.Background(), installFixture(BasicProfile, true), f)
				if e != ErrIndeterminate || p.Status != "indeterminate" || !p.MutationAttempted || !reflect.DeepEqual(f.events, order[:i+1]) {
					t.Fatalf("continued after uncertainty: %+v %v %v", p, e, f.events)
				}
				// A Claim failure before even its used fence cannot be modeled as positive
				// absence by a real adapter. Represent the retained uncertain fence explicitly.
				if event == "claim" && !after {
					f.snapshot.Custody = ""
				}
				f.events = nil
				f.failBefore = ""
				f.failAfter = ""
				p, e = Install(context.Background(), installFixture(BasicProfile, true), f)
				if len(f.events) > 0 || p.MutationAttempted {
					t.Fatal("replayed uncertainty")
				}
				// If the FINAL completed receipt was durable despite its reported error,
				// read-only inspection may establish that complete evidence already exists.
				if event == "receipt-4" && after {
					if e != nil || p.Status != "registration-confirmed" || !p.ReadOnly {
						t.Fatal("lost confirmed receipt")
					}
				} else if e == nil {
					t.Fatal("incomplete receipt claimed complete")
				}
			})
		}
	}
}
func TestImmutableOwnershipCannotAdoptReplacement(t *testing.T) {
	for _, mutate := range []func(*InstallRequest, *InstallSnapshot){
		func(r *InstallRequest, s *InstallSnapshot) { r.Selection.AgentSHA256 = strings.Repeat("d", 64) },
		func(r *InstallRequest, s *InstallSnapshot) { r.Selection.SourceSHA256 = strings.Repeat("d", 64) },
		func(r *InstallRequest, s *InstallSnapshot) { r.Selection.SourceArchive = "/Library/Reviewed/other.tar" },
		func(r *InstallRequest, s *InstallSnapshot) { r.Selection.ServiceIdentity = "511:511" },
		func(r *InstallRequest, s *InstallSnapshot) {
			r.Selection.Profile = InventoryProfile
			s.Config, _ = json.MarshalIndent(inventoryFixture(), "", "  ")
		},
		func(r *InstallRequest, s *InstallSnapshot) { s.EnrollmentAnchorSHA256 = strings.Repeat("d", 64) },
		func(r *InstallRequest, s *InstallSnapshot) {
			c := basicFixture()
			c.AgentID = "agent_" + strings.Repeat("2", 32)
			s.Config, _ = json.Marshal(c)
		},
	} {
		f := newLifecycleFake(BasicProfile)
		r := installFixture(BasicProfile, true)
		if _, e := Install(context.Background(), r, f); e != nil {
			t.Fatal(e)
		}
		f.events = nil
		mutate(&r, &f.snapshot)
		if _, e := Install(context.Background(), r, f); e != ErrCollision || len(f.events) > 0 {
			t.Fatal("adopted replacement")
		}
	}
}
func TestReceiptCorruptionAndRuntimeDriftNeverRepair(t *testing.T) {
	for _, change := range []func(*InstallSnapshot){
		func(s *InstallSnapshot) { s.Receipts = s.Receipts[:3] },
		func(s *InstallSnapshot) { s.Receipts[0].OwnershipSHA256 = strings.Repeat("d", 64) },
		func(s *InstallSnapshot) { s.Receipts[0], s.Receipts[1] = s.Receipts[1], s.Receipts[0] },
		func(s *InstallSnapshot) { s.Receipts = append(s.Receipts, s.Receipts[0]) },
		func(s *InstallSnapshot) { s.Job = Absent; s.JobOwnershipSHA256 = "" },
		func(s *InstallSnapshot) { s.JobOwnershipSHA256 = strings.Repeat("d", 64) },
		func(s *InstallSnapshot) { s.PlistSHA256 = strings.Repeat("d", 64) },
		func(s *InstallSnapshot) { s.Override = Present },
	} {
		f := newLifecycleFake(BasicProfile)
		r := installFixture(BasicProfile, true)
		if _, e := Install(context.Background(), r, f); e != nil {
			t.Fatal(e)
		}
		f.events = nil
		change(&f.snapshot)
		if _, e := Install(context.Background(), r, f); e == nil || len(f.events) > 0 {
			t.Fatal("repaired corrupt/changed state")
		}
	}
}
func TestEachTransitionRevalidatesSelection(t *testing.T) {
	for read := 2; read <= 9; read++ {
		t.Run(fmt.Sprint(read), func(t *testing.T) {
			f := newLifecycleFake(BasicProfile)
			f.onRead = func(f *lifecycleFake) {
				if f.reads == read {
					f.snapshot.EnrollmentAnchorSHA256 = strings.Repeat("e", 64)
				}
			}
			p, e := Install(context.Background(), installFixture(BasicProfile, true), f)
			if f.reads != read {
				t.Fatalf("injection did not reach exact transition: got %d want %d", f.reads, read)
			}
			if e == nil || p.Status == "registration-confirmed" {
				t.Fatal("identity drift accepted")
			}
		})
	}
}
func TestCanonicalOwnershipAndReceiptDecoders(t *testing.T) {
	f := newLifecycleFake(BasicProfile)
	if _, e := Install(context.Background(), installFixture(BasicProfile, true), f); e != nil {
		t.Fatal(e)
	}
	owner := *f.snapshot.Owner
	implicit := owner
	implicit.CollectionProfile = ""
	badOwner, _ := json.Marshal(implicit)
	if _, e := DecodeOwnership(badOwner); e == nil {
		t.Fatal("implicit owner profile")
	}
	raw, _ := json.Marshal(owner)
	if o, e := DecodeOwnership(raw); e != nil || o != owner {
		t.Fatal("owner rejected")
	}
	for _, bad := range [][]byte{append(raw, '\n'), append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"label":"com.tracebolt.agent"}`)...), []byte(`{}`)} {
		if _, e := DecodeOwnership(bad); e == nil {
			t.Fatal("noncanonical owner")
		}
	}
	for _, r := range f.snapshot.Receipts {
		raw, _ := json.Marshal(r)
		if got, e := DecodeReceipt(raw, owner); e != nil || got != r {
			t.Fatal("receipt rejected")
		}
		if _, e := DecodeReceipt(append(raw, '\n'), owner); e == nil {
			t.Fatal("receipt noncanonical")
		}
	}
}
func TestCloseFailureAndCancellationRetainEvidence(t *testing.T) {
	f := newLifecycleFake(BasicProfile)
	f.closeError = true
	p, e := Install(context.Background(), installFixture(BasicProfile, true), f)
	if e != ErrIndeterminate || p.Status != "indeterminate" || len(f.snapshot.Receipts) != 4 {
		t.Fatal("close failure hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f = newLifecycleFake(BasicProfile)
	f.onRead = func(f *lifecycleFake) {
		if f.reads == 4 {
			cancel()
		}
	}
	p, e = Install(ctx, installFixture(BasicProfile, true), f)
	if e != ErrIndeterminate || p.Status != "indeterminate" || !reflect.DeepEqual(f.events, []string{"claim", "receipt-1"}) {
		t.Fatalf("cancelled mutation continued %v", f.events)
	}
}

func TestNativeBackendDoesNotExposeLifecycleMutation(t *testing.T) {
	if _, ok := NewNativeBackend().(InstallBackend); ok {
		t.Fatal("native lifecycle adapter requires its own reviewed implementation")
	}
}
