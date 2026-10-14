package macosservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
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
	s.RemovalReceipts = append([]RemovalReceipt{}, s.RemovalReceipts...)
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

func (f *lifecycleFake) AppendRemovalReceipt(_ context.Context, r RemovalReceipt) error {
	return f.effect(fmt.Sprint("removal-receipt-", r.Sequence), func() { f.snapshot.RemovalReceipts = append(f.snapshot.RemovalReceipts, r) })
}
func (f *lifecycleFake) Bootout(_ context.Context, _ Ownership) error {
	return f.effect("bootout", func() { f.snapshot.Job = Absent; f.snapshot.JobOwnershipSHA256 = "" })
}
func (f *lifecycleFake) RemoveOwnedPlist(_ context.Context, _ Ownership) error {
	return f.effect("remove-plist", func() { f.snapshot.Plist = Absent; f.snapshot.PlistSHA256 = "" })
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
	_, ok := NewNativeBackend().(InstallBackend)
	if ok != (runtime.GOOS == "darwin") {
		t.Fatal("native lifecycle adapter platform mismatch")
	}
}

func TestOwnedUninstallIsOneAttemptAndRetainsOwner(t *testing.T) {
	f := newLifecycleFake(BasicProfile)
	r := installFixture(BasicProfile, true)
	if _, e := Install(context.Background(), r, f); e != nil {
		t.Fatal(e)
	}
	before := *f.snapshot.Owner
	f.events = nil
	r.Apply = false
	p, e := Uninstall(context.Background(), r, f)
	if e != nil || p.Status != "owned-removal-ready" || len(f.events) != 0 {
		t.Fatalf("review: %+v %v %v", p, e, f.events)
	}
	r.Apply = true
	p, e = Uninstall(context.Background(), r, f)
	want := []string{"removal-receipt-1", "bootout", "removal-receipt-2", "removal-receipt-3", "remove-plist", "removal-receipt-4"}
	if e != nil || p.Status != "owned-removal-confirmed" || !p.MutationAttempted || !reflect.DeepEqual(f.events, want) || *f.snapshot.Owner != before || f.snapshot.Custody != Present || len(f.snapshot.Receipts) != 4 || len(f.snapshot.RemovalReceipts) != 4 {
		t.Fatalf("apply: %+v %v %v", p, e, f.events)
	}
	f.events = nil
	p, e = Uninstall(context.Background(), r, f)
	if e != nil || !p.ReadOnly || p.MutationAttempted || p.Status != "owned-removal-confirmed" || len(f.events) != 0 {
		t.Fatal("repeat removal mutated")
	}
	if _, e = Install(context.Background(), r, f); e == nil {
		t.Fatal("reinstalled tombstoned identity")
	}
}

func TestOwnedUninstallUncertaintyNeverRetries(t *testing.T) {
	events := []string{"removal-receipt-1", "bootout", "removal-receipt-2", "removal-receipt-3", "remove-plist", "removal-receipt-4"}
	for i, event := range events {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-after-%v", event, after), func(t *testing.T) {
				f := newLifecycleFake(BasicProfile)
				r := installFixture(BasicProfile, true)
				if _, e := Install(context.Background(), r, f); e != nil {
					t.Fatal(e)
				}
				f.events = nil
				if after {
					f.failAfter = event
				} else {
					f.failBefore = event
				}
				p, e := Uninstall(context.Background(), r, f)
				if e != ErrIndeterminate || p.Status != "indeterminate" || !p.MutationAttempted || !reflect.DeepEqual(f.events, events[:i+1]) {
					t.Fatalf("uncertain: %+v %v %v", p, e, f.events)
				}
				if i == 0 && !after {
					f.snapshot.RemovalReceipts = []RemovalReceipt{{Sequence: 1}}
				}
				f.failAfter = ""
				f.failBefore = ""
				f.events = nil
				p, e = Uninstall(context.Background(), r, f)
				if len(f.events) != 0 || p.MutationAttempted {
					t.Fatal("uncertain removal retried")
				}
				if i == len(events)-1 && after {
					if e != nil || p.Status != "owned-removal-confirmed" {
						t.Fatal("lost final receipt not reconciled")
					}
				} else if e == nil {
					t.Fatal("incomplete removal accepted")
				}
			})
		}
	}
}

func TestRegisteredHandoffRequiresExactOwnedBootstrapEvidence(t *testing.T) {
	f := newLifecycleFake(BasicProfile)
	r := installFixture(BasicProfile, true)
	if _, e := Install(context.Background(), r, f); e != nil {
		t.Fatal(e)
	}
	good := f.snapshot
	good.Receipts = append([]Receipt{}, good.Receipts[:3]...)
	if !allowRegisteredHandoff(r.Selection, good) {
		t.Fatal("healthy registered branch blocked")
	}
	for name, change := range map[string]func(*InstallSnapshot){
		"before-bootstrap": func(s *InstallSnapshot) { s.Receipts = s.Receipts[:2] },
		"foreign-job":      func(s *InstallSnapshot) { s.JobOwnershipSHA256 = strings.Repeat("f", 64) },
		"unknown-job":      func(s *InstallSnapshot) { s.Job = "" },
		"no-job":           func(s *InstallSnapshot) { s.Job = Absent; s.JobOwnershipSHA256 = "" },
		"plist-drift":      func(s *InstallSnapshot) { s.PlistSHA256 = strings.Repeat("f", 64) },
		"owner-drift": func(s *InstallSnapshot) {
			copy := *s.Owner
			copy.AgentSHA256 = strings.Repeat("f", 64)
			s.Owner = &copy
		},
		"receipt-drift":     func(s *InstallSnapshot) { s.Receipts[2].Status = "completed" },
		"retained-override": func(s *InstallSnapshot) { s.Override = Present },
		"partial-removal":   func(s *InstallSnapshot) { s.RemovalReceipts = expectedRemovalReceipts(*s.Owner)[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			s := good
			s.Receipts = append([]Receipt{}, good.Receipts...)
			change(&s)
			if allowRegisteredHandoff(r.Selection, s) {
				t.Fatal("unsafe no-lock branch admitted")
			}
		})
	}
	// Lock contention itself is deliberately absent from the selector. Without
	// exact job/plist/owner/receipt evidence the full locked validator remains
	// mandatory, so an arbitrary competing sender lock cannot create authority.
}

func TestHealthyStartedSenderLockUsesOnlyExactRegisteredBranch(t *testing.T) {
	f := newLifecycleFake(BasicProfile)
	r := installFixture(BasicProfile, true)
	if _, e := Install(context.Background(), r, f); e != nil {
		t.Fatal(e)
	}
	exact := f.snapshot
	activeCalls, fullCalls := 0, 0
	inspect := func(_ context.Context, _ Request, registered bool) (SelectionEvidence, error) {
		if registered {
			activeCalls++
			return SelectionEvidence{Config: exact.Config, EnrollmentAnchorSHA256: exact.EnrollmentAnchorSHA256}, nil
		}
		fullCalls++
		return SelectionEvidence{}, ErrPreflight // lifetime sender lock occupied
	}
	if _, e := inspectWithRegisteredHandoff(context.Background(), r.Selection, exact, inspect); e != nil || activeCalls != 1 || fullCalls != 0 {
		t.Fatal("exact registered sender could not hand off lock")
	}
	for _, change := range []func(*InstallSnapshot){func(s *InstallSnapshot) { s.Receipts = s.Receipts[:2] }, func(s *InstallSnapshot) { s.JobOwnershipSHA256 = "" }, func(s *InstallSnapshot) { s.Owner = nil }, func(s *InstallSnapshot) { s.Plist = Absent; s.PlistSHA256 = "" }} {
		s := exact
		change(&s)
		if _, e := inspectWithRegisteredHandoff(context.Background(), r.Selection, s, inspect); e == nil {
			t.Fatal("foreign or pre-bootstrap lock bypassed full validation")
		}
	}
	if activeCalls != 1 || fullCalls != 4 {
		t.Fatalf("wrong handoff routing active=%d full=%d", activeCalls, fullCalls)
	}
}

func TestNonrootSelectionRejectsNativeObservationDrift(t *testing.T) {
	f := newLifecycleFake(BasicProfile)
	r := installFixture(BasicProfile, true)
	if _, err := Install(context.Background(), r, f); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot
	child := func(_ context.Context, _ Request, registered bool) (SelectionEvidence, error) {
		if !registered {
			return SelectionEvidence{}, ErrPreflight
		}
		return SelectionEvidence{Config: before.Config, EnrollmentAnchorSHA256: before.EnrollmentAnchorSHA256}, nil
	}
	for name, change := range map[string]func(*InstallSnapshot){
		"job-disappeared":   func(s *InstallSnapshot) { s.Job = Absent; s.JobOwnershipSHA256 = "" },
		"foreign-job":       func(s *InstallSnapshot) { s.JobOwnershipSHA256 = strings.Repeat("f", 64) },
		"override-appeared": func(s *InstallSnapshot) { s.Override = Present },
		"plist-changed":     func(s *InstallSnapshot) { s.PlistSHA256 = strings.Repeat("f", 64) },
		"custody-changed":   func(s *InstallSnapshot) { s.Custody = Absent; s.Owner = nil },
		"owner-changed": func(s *InstallSnapshot) {
			owner := *s.Owner
			owner.AgentSHA256 = strings.Repeat("f", 64)
			s.Owner = &owner
		},
		"receipt-changed": func(s *InstallSnapshot) {
			s.Receipts = append([]Receipt{}, s.Receipts...)
			s.Receipts[3].Status = "started"
		},
		"removal-started": func(s *InstallSnapshot) { s.RemovalReceipts = expectedRemovalReceipts(*s.Owner)[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			change(&after)
			calls := 0
			read := func(context.Context) (InstallSnapshot, error) {
				calls++
				if calls == 1 {
					return before, nil
				}
				return after, nil
			}
			if _, err := inspectStableSelection(context.Background(), r.Selection, read, child); err != ErrPreflight || calls != 2 {
				t.Fatalf("accepted drift or skipped re-read: err=%v calls=%d", err, calls)
			}
		})
	}
	reads := 0
	read := func(context.Context) (InstallSnapshot, error) { reads++; return before, nil }
	got, err := inspectStableSelection(context.Background(), r.Selection, read, child)
	if err != nil || reads != 2 || !got.PrerequisitesVerified || got.Job != Present || got.JobOwnershipSHA256 == "" {
		t.Fatalf("unchanged exact job failed: %+v %v reads=%d", got, err, reads)
	}
}

func TestExpectedPresentPlistStillChecksFinalDirectories(t *testing.T) {
	calls := 0
	changedDirectory := func() bool { calls++; return false }
	if finalSelectionPaths(true, false, false, changedDirectory) || calls != 1 {
		t.Fatal("expected-present plist bypassed changed directory")
	}
	if finalSelectionPaths(true, false, true, func() bool { return true }) {
		t.Fatal("fresh planning accepted present plist")
	}
	if finalSelectionPaths(false, false, false, func() bool { return true }) {
		t.Fatal("unknown plist status accepted")
	}
	if !finalSelectionPaths(true, false, false, func() bool { return true }) || !finalSelectionPaths(true, true, true, func() bool { return true }) {
		t.Fatal("known safe lifecycle or fresh path rejected")
	}
}

func TestOnlyRegisteredPrivateDirectoriesMayAdvanceMetadata(t *testing.T) {
	for _, name := range []string{StateDirectory, EnrollmentDirectory, EnrollmentDirectory + "/telemetry"} {
		if !mutableSelectionDirectory(name, true) || mutableSelectionDirectory(name, false) {
			t.Fatalf("wrong phase rule for %s", name)
		}
	}
	for _, name := range []string{"/", "/Library", "/Library/Application Support", InstallDirectory, "/Library/LaunchDaemons", "/Library/Application Support/TraceboltAgentX/state"} {
		if mutableSelectionDirectory(name, true) {
			t.Fatalf("relaxed root-owned or unrelated directory %s", name)
		}
	}
}
