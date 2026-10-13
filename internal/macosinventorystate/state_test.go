package macosinventorystate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	inventory "localrmm/internal/macosinventory"
	wire "localrmm/internal/macosinventorywire"
)

// memoryCommitter models the required durable boundary; it does not prove any
// filesystem, sync, ACL, process-lock or power-loss property.
type memoryCommitter struct {
	mu            sync.Mutex
	used          bool
	raw           []byte
	commits       int
	fail          bool
	writeThenFail bool
	before        func([]byte)
}

var privateFailure = errors.New("PRIVATE_PROVIDER_TEXT_NOT_FOR_ERRORS")

func (m *memoryCommitter) CreateFresh(next []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.used || len(m.raw) != 0 {
		return privateFailure
	}
	// The irreversible primary fence precedes checkpoint creation, including a
	// failure before checkpoint publication. Missing used checkpoint cannot reset.
	m.used = true
	if m.fail && !m.writeThenFail {
		return privateFailure
	}
	m.raw = bytes.Clone(next)
	m.commits++
	if m.fail {
		return privateFailure
	}
	return nil
}
func (m *memoryCommitter) Commit(expected, next []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.used || len(m.raw) == 0 || !bytes.Equal(expected, m.raw) {
		return privateFailure
	}
	if m.before != nil {
		m.before(next)
	}
	if m.fail && !m.writeThenFail {
		return privateFailure
	}
	m.raw = bytes.Clone(next)
	m.commits++
	if m.fail {
		return privateFailure
	}
	return nil
}
func (m *memoryCommitter) snapshot() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return bytes.Clone(m.raw)
}
func control() wire.Control {
	return wire.Control{SchemaVersion: wire.ControlVersion, Binding: wire.Binding{Platform: wire.Platform, Profile: wire.Profile, DeviceID: "agent_" + strings.Repeat("a", 32), SenderBinding: strings.Repeat("b", 64)}, GrantID: strings.Repeat("c", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
}
func enableBytes(t *testing.T) []byte {
	t.Helper()
	b, e := wire.EncodeControl(control())
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func ackBytes(t *testing.T, request []byte, at time.Time) []byte {
	t.Helper()
	a, e := wire.ReceiptFor(request, at)
	if e != nil {
		t.Fatal(e)
	}
	b, e := wire.EncodeReceipt(a, request)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fresh(t *testing.T, enabled bool) (*State, *memoryCommitter) {
	t.Helper()
	m := &memoryCommitter{}
	s, e := InitializeFresh(m, enableBytes(t), control().ChangedAt)
	if e != nil {
		t.Fatal(e)
	}
	if enabled {
		if e := s.AcknowledgeControl(ackBytes(t, enableBytes(t), control().ChangedAt), control().ChangedAt); e != nil {
			t.Fatal(e)
		}
	}
	return s, m
}
func reserve(t *testing.T, s *State, at time.Time) Lease {
	t.Helper()
	l, e := s.Reserve(at)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func snapshot(l Lease) inventory.Snapshot {
	status := func(src string) inventory.Status { return inventory.Status{Source: src, Quality: "observed"} }
	return inventory.Snapshot{SchemaVersion: inventory.SchemaVersion, Scope: inventory.Scope, GrantID: control().GrantID, GenerationID: l.GenerationID(), CollectedAt: l.CollectedAt(),
		Hardware:  inventory.Hardware{Status: status(inventory.HardwareSource), ModelIdentifier: "Mac14,2", PhysicalCPUs: 8, LogicalCPUs: 8, MemoryCapacityBytes: 1 << 34},
		Receipts:  inventory.Receipts{Status: status(inventory.ReceiptSource), Identifiers: []string{"org.example.app"}},
		Processes: inventory.Processes{Status: status(inventory.ProcessSource), Rows: []inventory.Process{{PID: 1, ParentPID: 0, AccountingName: "launchd", NameQuality: "observed"}}},
		Network:   inventory.Network{IPv4: inventory.Interfaces{Status: status(inventory.IPv4Source), Rows: []inventory.Interface{{Name: "en0", MTU: 1500, Addresses: []inventory.Address{}}}}, IPv6: inventory.Interfaces{Status: status(inventory.IPv6Source), Rows: []inventory.Interface{{Name: "en0", MTU: 1500, Addresses: []inventory.Address{}}}}}}
}
func reportBytes(t *testing.T, l Lease, change func(*inventory.Snapshot)) []byte {
	t.Helper()
	snap := snapshot(l)
	if change != nil {
		change(&snap)
	}
	r, e := wire.BuildReport(control(), l.Sequence(), snap)
	if e != nil {
		t.Fatal(e)
	}
	b, e := wire.EncodeReport(r)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func stage(t *testing.T, s *State, at time.Time) (Lease, []byte) {
	t.Helper()
	l := reserve(t, s, at)
	b := reportBytes(t, l, nil)
	if e := s.Stage(l, b, at); e != nil {
		t.Fatal(e)
	}
	return l, b
}
func reopen(t *testing.T, s *State, m *memoryCommitter, at time.Time) *State {
	t.Helper()
	s.Close()
	out, e := Restore(m, enableBytes(t), m.snapshot(), at)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestFreshMustCommitAndAcknowledgeEnableBeforeCollection(t *testing.T) {
	s, m := fresh(t, false)
	at := control().ChangedAt
	if m.commits != 1 || !m.used {
		t.Fatal("initial used checkpoint not committed")
	}
	if l, e := s.Reserve(at); e != ErrNotEnabled || l != (Lease{}) {
		t.Fatal("unacknowledged enable returned lease", e)
	}
	b, e := s.PendingControl(at)
	if e != nil || !bytes.Equal(b, enableBytes(t)) {
		t.Fatal(e)
	}
	// A future receivedAt cannot be made true by caller-supplied receipt bytes.
	future := ackBytes(t, b, at.Add(time.Second))
	if e := s.AcknowledgeControl(future, at); e != ErrInvalid {
		t.Fatal(e)
	}
	if e := s.AcknowledgeControl(ackBytes(t, b, at), at); e != nil {
		t.Fatal(e)
	}
	seen := false
	m.before = func(next []byte) {
		c, e := decode(next)
		if e != nil || c.Floor != 1 || c.Attempt.Status != "reserved" {
			t.Fatal("lease preceded reservation", e)
		}
		seen = true
	}
	l := reserve(t, s, at)
	m.before = nil
	if !seen || l.Sequence() != 1 || l.CollectedAt() != at || l.GenerationID() == "" {
		t.Fatal("reservation metadata")
	}
	if _, e := s.Reserve(at.Add(time.Minute)); e != ErrBusy {
		t.Fatal(e)
	}
	if _, e := s.PendingControl(at); e != ErrNoPending {
		t.Fatal(e)
	}
}
func TestMissingUsedStateCannotBecomeFresh(t *testing.T) {
	s, m := fresh(t, true)
	s.Close()
	m.raw = nil
	if _, e := Restore(m, enableBytes(t), nil, control().ChangedAt); e != ErrMissing {
		t.Fatal(e)
	}
	if _, e := InitializeFresh(m, enableBytes(t), control().ChangedAt); e != ErrUncertain {
		t.Fatal("used marker reset", e)
	}
	for _, after := range []bool{false, true} {
		broken := &memoryCommitter{fail: true, writeThenFail: after}
		if got, e := InitializeFresh(broken, enableBytes(t), control().ChangedAt); got != nil || e != ErrUncertain {
			t.Fatal(e)
		}
		broken.fail = false
		if _, e := InitializeFresh(broken, enableBytes(t), control().ChangedAt); e != ErrUncertain {
			t.Fatal("uncertain initialization reset")
		}
	}
}
func TestLostReservationConsumesFloorAndPacingAcrossReopen(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	l := reserve(t, s, at)
	s = reopen(t, s, m, at.Add(time.Second))
	v, e := s.Inspect(at.Add(time.Second))
	if e != nil || v.Floor != 1 || v.AttemptStatus != "lost" || v.FailureReason != FailureInterrupted || v.LastCaptureAt != at {
		t.Fatal(v, e)
	}
	if e := s.Stage(l, reportBytes(t, l, nil), at.Add(time.Second)); e != ErrConflict {
		t.Fatal("old lease adopted", e)
	}
	if _, e := s.Reserve(at.Add(time.Minute - time.Nanosecond)); e != ErrPacing {
		t.Fatal(e)
	}
	l = reserve(t, s, at.Add(time.Minute))
	if l.Sequence() != 2 {
		t.Fatal("lost sequence reused")
	}
	if e := s.Fail(l, FailureCollection, at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, m, at.Add(time.Minute))
	l = reserve(t, s, at.Add(2*time.Minute))
	if l.Sequence() != 3 {
		t.Fatal("failure floor lost")
	}
	if e := s.Fail(l, FailureReason("PRIVATE_PROVIDER_TEXT_NOT_FOR_ERRORS"), at.Add(2*time.Minute)); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestExactPendingAndReceiptsAcrossReopenAndRenewal(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	_, want := stage(t, s, at)
	original := m.snapshot()
	s = reopen(t, s, m, at)
	if !bytes.Equal(m.snapshot(), original) {
		t.Fatal("reopen changed exact pending state")
	}
	for _, when := range []time.Time{at, at.Add(time.Minute), at.Add(2 * time.Minute)} {
		got, e := s.PendingReport(when)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("retry rewritten", e)
		}
	}
	// There is no current-leaf field to rebind on renewal. Only the original
	// initializer anchor opens this checkpoint; replacing it fails closed.
	changed := control()
	changed.Binding.SenderBinding = strings.Repeat("d", 64)
	foreign, _ := wire.EncodeControl(changed)
	if _, e := Restore(m, foreign, m.snapshot(), at.Add(2*time.Minute)); e != ErrConflict {
		t.Fatal("renewed leaf adopted as original binding", e)
	}
	ack := ackBytes(t, want, at.Add(time.Second))
	if e := s.AcknowledgeReport(ack, at.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, m, at.Add(3*time.Minute))
	cp, e := decode(m.snapshot())
	if e != nil || !bytes.Equal(cp.Report.Body, want) || !bytes.Equal(cp.Report.Receipt, ack) {
		t.Fatal("receipt/body changed", e)
	}
	if e := s.AcknowledgeReport(ack, at.Add(3*time.Minute)); e != nil {
		t.Fatal("exact receipt duplicate", e)
	}
	altered := ackBytes(t, want, at.Add(2*time.Second))
	if e := s.AcknowledgeReport(altered, at.Add(3*time.Minute)); e != ErrConflict {
		t.Fatal("receipt timestamp rewritten", e)
	}
	if _, e := s.PendingReport(at.Add(3 * time.Minute)); e != ErrNoPending {
		t.Fatal(e)
	}
	l := reserve(t, s, at.Add(3*time.Minute))
	if l.Sequence() != 2 {
		t.Fatal("ack reset floor")
	}
}
func TestReceiptMustBindExactPendingBytesAndTime(t *testing.T) {
	s, _ := fresh(t, true)
	at := control().ChangedAt
	l, raw := stage(t, s, at)
	altered := reportBytes(t, l, func(v *inventory.Snapshot) { v.Hardware.ModelIdentifier = "Mac15,2" })
	for _, ack := range [][]byte{ackBytes(t, altered, at), ackBytes(t, raw, at.Add(time.Second)), ackBytes(t, enableBytes(t), at), []byte(`{"private":"PRIVATE_PROVIDER_TEXT_NOT_FOR_ERRORS"}`)} {
		if e := s.AcknowledgeReport(ack, at); e != ErrInvalid {
			t.Fatal("unbound/future receipt", e)
		}
	}
	if e := s.AcknowledgeReport(ackBytes(t, raw, at), at); e != nil {
		t.Fatal(e)
	}
}
func TestTerminalDisableAllPhasesAndExactControlRetry(t *testing.T) {
	for _, phase := range []string{"fresh", "reserved", "failed", "pending", "recorded"} {
		t.Run(phase, func(t *testing.T) {
			s, m := fresh(t, phase != "fresh")
			at := control().ChangedAt
			var l Lease
			var body []byte
			floor := uint64(0)
			if phase != "fresh" {
				l = reserve(t, s, at)
				floor = 1
			}
			if phase == "failed" {
				if e := s.Fail(l, FailureCollection, at); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "pending" || phase == "recorded" {
				body = reportBytes(t, l, nil)
				if e := s.Stage(l, body, at); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "recorded" {
				if e := s.AcknowledgeReport(ackBytes(t, body, at), at); e != nil {
					t.Fatal(e)
				}
			}
			off, e := s.Disable(at.Add(time.Second))
			if e != nil {
				t.Fatal(e)
			}
			c, e := wire.DecodeControl(off)
			if e != nil || c.CaptureFloor != floor || c.Enabled {
				t.Fatal("bad final floor", e)
			}
			s = reopen(t, s, m, at.Add(2*time.Second))
			again, e := s.Disable(at.Add(3 * time.Second))
			if e != nil || !bytes.Equal(again, off) {
				t.Fatal("disable timestamp changed", e)
			}
			pending, e := s.PendingControl(at.Add(3 * time.Second))
			if e != nil || !bytes.Equal(pending, off) {
				t.Fatal("wrong pending control", e)
			}
			if _, e := s.Reserve(at.Add(time.Minute)); e != ErrDisabled {
				t.Fatal(e)
			}
			if _, e := s.PendingReport(at.Add(time.Minute)); e != ErrDisabled {
				t.Fatal(e)
			}
			if e := s.Stage(l, body, at.Add(time.Minute)); e != ErrDisabled {
				t.Fatal(e)
			}
			if e := s.AcknowledgeReport(nil, at.Add(time.Minute)); e != ErrDisabled {
				t.Fatal(e)
			}
			ack := ackBytes(t, off, at.Add(3*time.Second))
			if e := s.AcknowledgeControl(ack, at.Add(time.Minute)); e != nil {
				t.Fatal(e)
			}
			s = reopen(t, s, m, at.Add(time.Minute))
			cp, _ := decode(m.snapshot())
			if !bytes.Equal(cp.DisableReceipt, ack) || cp.Floor != floor || !cp.Used {
				t.Fatal("terminal tombstones changed")
			}
			if _, e := s.PendingControl(at.Add(time.Minute)); e != ErrNoPending {
				t.Fatal(e)
			}
			if e := s.AcknowledgeControl(ackBytes(t, enableBytes(t), at), at.Add(time.Minute)); e != ErrInvalid {
				t.Fatal("reenable receipt", e)
			}
		})
	}
}
func TestRetentionQualityAndFailedSiblingPreserveOriginalAge(t *testing.T) {
	for _, quality := range []string{"full", "partial", "unknown"} {
		t.Run(quality, func(t *testing.T) {
			s, m := fresh(t, true)
			at := control().ChangedAt
			l := reserve(t, s, at)
			raw := reportBytes(t, l, func(v *inventory.Snapshot) {
				if quality != "full" {
					v.Hardware = inventory.EmptyHardware(inventory.ErrDenied.Error())
				}
				if quality == "unknown" {
					v.Receipts = inventory.EmptyReceipts(inventory.ErrDenied.Error())
					v.Processes = inventory.EmptyProcesses(inventory.ErrDenied.Error())
					v.Network = inventory.EmptyNetwork(inventory.ErrDenied.Error())
				}
			})
			if e := s.Stage(l, raw, at); e != nil {
				t.Fatal(e)
			}
			for _, tc := range []struct {
				delta     time.Duration
				freshness string
			}{{0, "fresh"}, {time.Minute - time.Nanosecond, "fresh"}, {time.Minute, "stale"}, {wire.Retention - time.Nanosecond, "stale"}, {wire.Retention, "expired"}} {
				v, e := s.Inspect(at.Add(tc.delta))
				if e != nil || v.SourceQuality != quality || v.Freshness != tc.freshness {
					t.Fatal(v, e)
				}
			}
			if got, e := s.PendingReport(at.Add(wire.Retention)); got != nil || e != ErrExpired {
				t.Fatal("expired retry", e)
			}
			c, e := decode(m.snapshot())
			if e != nil || c.Report.Body != nil || c.Floor != 1 || c.Attempt.Status != "expired" {
				t.Fatal("expiry lost floor", e)
			}
			s = reopen(t, s, m, at.Add(wire.Retention))
			l = reserve(t, s, at.Add(wire.Retention))
			if l.Sequence() != 2 {
				t.Fatal("expiry reset")
			}
		})
	}
	s, m := fresh(t, true)
	at := control().ChangedAt
	_, raw := stage(t, s, at)
	ack := ackBytes(t, raw, at)
	if e := s.AcknowledgeReport(ack, at); e != nil {
		t.Fatal(e)
	}
	l := reserve(t, s, at.Add(time.Minute))
	if e := s.Fail(l, FailureCollection, at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	v, e := s.Inspect(at.Add(time.Minute))
	if e != nil || v.ReportSequence != 1 || v.Floor != 2 || v.Freshness != "stale" {
		t.Fatal(v, e)
	}
	if _, e := s.Inspect(at.Add(wire.Retention)); e != nil {
		t.Fatal(e)
	}
	c, e := decode(m.snapshot())
	if e != nil || c.Report.Body != nil || !bytes.Equal(c.Report.Receipt, ack) {
		t.Fatal("original receipt not retained after data expiry", e)
	}
	s = reopen(t, s, m, at.Add(wire.Retention))
	if _, e := s.Disable(at.Add(wire.Retention)); e != nil {
		t.Fatal(e)
	}
}
func TestImmutableCopiesAndStateRedaction(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	l := reserve(t, s, at)
	raw := reportBytes(t, l, nil)
	want := bytes.Clone(raw)
	if e := s.Stage(l, raw, at); e != nil {
		t.Fatal(e)
	}
	clear(raw)
	got, e := s.PendingReport(at)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("input alias", e)
	}
	clear(got)
	cp, e := s.CheckpointBytes()
	if e != nil {
		t.Fatal(e)
	}
	clear(cp)
	got, e = s.PendingReport(at)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("output alias", e)
	}
	ack := ackBytes(t, want, at)
	originalAck := bytes.Clone(ack)
	if e := s.AcknowledgeReport(ack, at); e != nil {
		t.Fatal(e)
	}
	clear(ack)
	c, e := decode(m.snapshot())
	if e != nil || !bytes.Equal(c.Report.Receipt, originalAck) {
		t.Fatal("receipt alias", e)
	}
	b, _ := json.Marshal(s)
	for _, v := range []string{fmt.Sprintf("%+v %#v %s", s, s, s), string(b)} {
		if strings.Contains(v, "launchd") || strings.Contains(v, control().Binding.DeviceID) {
			t.Fatal("state formatter leaked source")
		}
	}
	s.Close()
	if got, e := s.CheckpointBytes(); got != nil || e != ErrClosed {
		t.Fatal(e)
	}
}

func TestCommitFailurePoisonsAllOperationsAndNeverReturnsWork(t *testing.T) {
	for _, after := range []bool{false, true} {
		for _, operation := range []string{"reserve", "stage", "fail", "report_retry", "control_retry", "ack_report", "ack_control", "disable", "inspect", "expire", "restore"} {
			t.Run(fmt.Sprintf("%s/after=%v", operation, after), func(t *testing.T) {
				s, m := fresh(t, operation != "ack_control" && operation != "control_retry")
				at := control().ChangedAt
				var l Lease
				var raw []byte
				switch operation {
				case "stage", "fail", "restore":
					l = reserve(t, s, at)
					raw = reportBytes(t, l, nil)
				case "report_retry", "ack_report", "expire":
					l, raw = stage(t, s, at)
				}
				m.fail, m.writeThenFail = true, after
				now := at.Add(time.Second)
				var e error
				var work []byte
				switch operation {
				case "reserve":
					var lease Lease
					lease, e = s.Reserve(now)
					if lease != (Lease{}) {
						t.Fatal("uncertain lease escaped")
					}
				case "stage":
					e = s.Stage(l, raw, now)
				case "fail":
					e = s.Fail(l, FailureCollection, now)
				case "report_retry":
					work, e = s.PendingReport(now)
				case "control_retry":
					work, e = s.PendingControl(now)
				case "ack_report":
					e = s.AcknowledgeReport(ackBytes(t, raw, at), now)
				case "ack_control":
					e = s.AcknowledgeControl(ackBytes(t, enableBytes(t), at), now)
				case "disable":
					work, e = s.Disable(now)
				case "inspect":
					_, e = s.Inspect(now)
				case "expire":
					work, e = s.PendingReport(at.Add(wire.Retention))
					now = at.Add(wire.Retention)
				case "restore":
					var reopened *State
					reopened, e = Restore(m, enableBytes(t), m.snapshot(), now)
					if reopened != nil {
						t.Fatal("uncertain restore returned state")
					}
					returnAfterRestore(t, e)
					return
				}
				if e != ErrUncertain || work != nil {
					t.Fatal("failed commit exposed work", e)
				}
				m.fail = false // A backend recovery does NOT unpoison this owner.
				if l, e := s.Reserve(now); e != ErrUncertain || l != (Lease{}) {
					t.Fatal(e)
				}
				if b, e := s.PendingReport(now); e != ErrUncertain || b != nil {
					t.Fatal(e)
				}
				if b, e := s.PendingControl(now); e != ErrUncertain || b != nil {
					t.Fatal(e)
				}
				if b, e := s.Disable(now); e != ErrUncertain || b != nil {
					t.Fatal(e)
				}
				if _, e := s.Inspect(now); e != ErrUncertain {
					t.Fatal(e)
				}
				if _, e := s.CheckpointBytes(); e != ErrUncertain {
					t.Fatal(e)
				}
				if e := s.AcknowledgeControl(nil, now); e != ErrUncertain {
					t.Fatal(e)
				}
				if e := s.AcknowledgeReport(nil, now); e != ErrUncertain {
					t.Fatal(e)
				}
				if e := s.Stage(l, nil, now); e != ErrUncertain {
					t.Fatal(e)
				}
				if e := s.Fail(l, FailureInterrupted, now); e != ErrUncertain {
					t.Fatal(e)
				}
			})
		}
	}
}
func returnAfterRestore(t *testing.T, e error) {
	t.Helper()
	if e != ErrUncertain {
		t.Fatal(e)
	}
}

func TestConcurrentReserveDisableAndAcknowledgement(t *testing.T) {
	for i := 0; i < 80; i++ {
		s, m := fresh(t, true)
		at := control().ChangedAt
		ack := ackBytes(t, enableBytes(t), at)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, e := s.Reserve(at)
			if e != nil && e != ErrDisabled {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			_, e := s.Disable(at)
			if e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			e := s.AcknowledgeControl(ack, at)
			if e != nil && e != ErrInvalid {
				t.Error(e)
			}
		}()
		wg.Wait()
		c, e := decode(m.snapshot())
		if e != nil || c.Disable == nil || c.Floor > 1 || c.Attempt != nil && c.Attempt.Status != "lost" {
			t.Fatal("nonserialized reserve/disable", e)
		}
		if _, e := s.Reserve(at.Add(time.Minute)); e != ErrDisabled {
			t.Fatal(e)
		}
	}
	for i := 0; i < 80; i++ {
		s, m := fresh(t, true)
		at := control().ChangedAt
		_, raw := stage(t, s, at)
		ack := ackBytes(t, raw, at)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			e := s.AcknowledgeReport(ack, at)
			if e != nil && e != ErrDisabled {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			_, e := s.Disable(at)
			if e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			_, e := s.Reserve(at)
			if e != ErrDisabled && e != ErrBusy && e != ErrPacing {
				t.Error(e)
			}
		}()
		wg.Wait()
		c, e := decode(m.snapshot())
		if e != nil || c.Disable == nil || c.Floor != 1 || c.Attempt.Status != "recorded" && c.Attempt.Status != "abandoned" {
			t.Fatal("nonserialized ack/disable", e)
		}
		if _, e := s.PendingReport(at); e != ErrDisabled {
			t.Fatal(e)
		}
	}
}
func TestConcurrentReservationReturnsOnlyOneLease(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	var wg sync.WaitGroup
	leases := make(chan Lease, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, e := s.Reserve(at)
			if e == nil {
				leases <- l
			} else if e != ErrBusy {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	close(leases)
	if len(leases) != 1 {
		t.Fatal("multiple leases", len(leases))
	}
	c, e := decode(m.snapshot())
	if e != nil || c.Floor != 1 {
		t.Fatal(e)
	}
}

func TestExactNoOpStillVerifiesDurableCheckpointAndRejectsRollback(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	_, want := stage(t, s, at)
	stale := m.snapshot()
	// Missing state cannot be hidden by a byte-identical retry at the same time.
	m.raw = nil
	if got, e := s.PendingReport(at); got != nil || e != ErrUncertain {
		t.Fatal("missing checkpoint yielded report", e)
	}
	m.raw = stale
	if _, e := s.PendingReport(at); e != ErrUncertain {
		t.Fatal("uncertainty unpoisoned", e)
	}
	s.Close()
	s, e := Restore(m, enableBytes(t), stale, at)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.AcknowledgeReport(ackBytes(t, want, at), at); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if got, e := Restore(m, enableBytes(t), stale, at); got != nil || e != ErrUncertain {
		t.Fatal("stale snapshot reopened over newer receipt", e)
	}
}

func TestAmbiguousReserveConsumesSequenceWithoutReturningLease(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	m.fail, m.writeThenFail = true, true
	if l, e := s.Reserve(at); l != (Lease{}) || e != ErrUncertain {
		t.Fatal(e)
	}
	m.fail = false
	s = reopen(t, s, m, at)
	v, e := s.Inspect(at)
	if e != nil || v.Floor != 1 || v.AttemptStatus != "lost" {
		t.Fatal("ambiguous committed reservation reset", v, e)
	}
	if l, e := s.Reserve(at.Add(time.Minute)); e != nil || l.Sequence() != 2 {
		t.Fatal(e)
	}
}

type panicCommitter struct {
	memory *memoryCommitter
	after  bool
	armed  bool
}

func (p *panicCommitter) CreateFresh(next []byte) error { return p.memory.CreateFresh(next) }
func (p *panicCommitter) Commit(expected, next []byte) error {
	if !p.armed {
		return p.memory.Commit(expected, next)
	}
	if p.after {
		if e := p.memory.Commit(expected, next); e != nil {
			return e
		}
	}
	panic(privateFailure)
}
func TestRecoveredAdapterPanicLeavesLiveOwnerPoisoned(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			at := control().ChangedAt
			m := &memoryCommitter{}
			p := &panicCommitter{memory: m, after: after}
			s, e := InitializeFresh(p, enableBytes(t), at)
			if e != nil {
				t.Fatal(e)
			}
			if e := s.AcknowledgeControl(ackBytes(t, enableBytes(t), at), at); e != nil {
				t.Fatal(e)
			}
			p.armed = true
			recovered := false
			func() {
				defer func() {
					if recover() != nil {
						recovered = true
					}
				}()
				_, _ = s.Reserve(at)
			}()
			if !recovered {
				t.Fatal("fixture did not panic")
			}
			p.armed = false
			if l, e := s.Reserve(at); l != (Lease{}) || e != ErrUncertain {
				t.Fatal("panic owner recovered usable lease", e)
			}
			if b, e := s.PendingControl(at); b != nil || e != ErrUncertain {
				t.Fatal(e)
			}
			if b, e := s.PendingReport(at); b != nil || e != ErrUncertain {
				t.Fatal(e)
			}
			if b, e := s.CheckpointBytes(); b != nil || e != ErrUncertain {
				t.Fatal("panic owner exposed stale state", e)
			}
			s.Close()
			reopened, e := Restore(p, enableBytes(t), m.snapshot(), at)
			if e != nil {
				t.Fatal(e)
			}
			v, e := reopened.Inspect(at)
			if e != nil {
				t.Fatal(e)
			}
			if after && (v.Floor != 1 || v.AttemptStatus != "lost") || !after && v.Floor != 0 {
				t.Fatal("actual commit outcome not preserved", v)
			}
		})
	}
}
