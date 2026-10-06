package completeoverview

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestProcessCommNamesAndLinuxStates(t *testing.T) {
	states := map[string]string{"R": "running", "S": "sleeping", "D": "disk_sleep", "T": "stopped", "t": "tracing_stop", "Z": "zombie", "X": "dead", "x": "dead", "I": "idle", "P": "parked"}
	for _, name := range []string{"systemd", "kthreadd", "pool_workqueue_release", "kworker/0:0", "kworker/0:0H", "kworker/u8:0-events_unbound", "rcu_exp_par_gp_kthread_worker/0", "migration/0", "jbd2/sda1-8", `literal\name`, "name with ) paren/0", strings.Repeat("x", MaxProcessNameBytes), "../label", "<tag/name>"} {
		for code, state := range states {
			t.Run(name+"_"+code, func(t *testing.T) {
				raw := strings.Replace(statFixture(42, name), ") S ", ") "+code+" ", 1)
				p, err := ParseProcessStat([]byte(raw), 42, 4096, 100)
				if err != nil {
					t.Fatalf("valid comm rejected: %v", err)
				}
				if p.Name == nil || *p.Name != name || p.State == nil || *p.State != state || *p.RSSBytes != 32768 || *p.CPUTimeSeconds != 2 || *p.Threads != 3 || ValidateProcess(p) != nil {
					t.Fatalf("comm or metrics changed: %+v", p)
				}
			})
		}
	}
}

func TestProcessCommCollectionCoverageAndStrictRoundTrip(t *testing.T) {
	// Invented rows reproduce the reported 56 observed / 73 invalid split on the
	// old parser, solely by varying comm punctuation. These are not host captures.
	p := &fixtureProvider{count: 129, statData: map[uint32]string{}}
	for pid := uint32(1); pid <= 129; pid++ {
		name := fmt.Sprintf("fixture-%d", pid)
		if pid > 56 {
			name = fmt.Sprintf("kworker/%d:0", pid-57)
		}
		p.statData[pid] = strings.Replace(statFixture(pid, name), ") S ", ") I ", 1)
	}
	s := runFixture(t, p)
	if s.Processes.Meta.FieldCoverage != (FieldCoverage{Observed: 129}) || *s.Processes.Meta.ObservedCount != 129 {
		t.Fatalf("valid kernel comms lost: %+v", s.Processes.Meta)
	}
	raw, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeStrict(raw)
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("strict snapshot round trip: %v", err)
	}
}

func TestProcessCommRetainsUnsafeTextAndUnknownOutcomes(t *testing.T) {
	valid, err := ParseProcessStat([]byte(statFixture(42, "fixture")), 42, 4096, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", strings.Repeat("x", MaxProcessNameBytes+1), "bad\nname", "bad\x00name", "bad\u202ename", "bad\u2028name", "bad\ufffdname", "bad\xffname"} {
		valid.Name = &name
		if ValidateProcess(valid) == nil {
			t.Fatalf("unsafe wire comm accepted: %q", name)
		}
		if _, err := ParseProcessStat([]byte(statFixture(42, name)), 42, 4096, 100); err != ErrInvalidSource {
			t.Fatalf("unsafe comm accepted: %q, %v", name, err)
		}
	}
	p := &fixtureProvider{count: 4, statData: map[uint32]string{
		1: statFixture(1, "kworker/0:0"),
		2: strings.Replace(statFixture(2, "kworker/0:1"), ") S ", ") ? ", 1),
		3: statFixture(3, "bad\nname"),
	}, statErr: map[uint32]error{4: SourceError{ReasonPermissionDenied}}}
	s := runFixture(t, p)
	if s.Processes.Meta.FieldCoverage != (FieldCoverage{Observed: 1, Unsupported: 1, Invalid: 1, Denied: 1}) {
		t.Fatalf("unknown outcomes changed: %+v", s.Processes.Meta.FieldCoverage)
	}
	for _, row := range s.Processes.Items[1:] {
		if row.Name != nil || row.State != nil || row.ParentPID != nil || row.RSSBytes != nil || row.CPUTimeSeconds != nil || row.Threads != nil {
			t.Fatal("unobserved fields fabricated")
		}
	}
}
