package macosinventorystate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	inventory "localrmm/internal/macosinventory"
	wire "localrmm/internal/macosinventorywire"
)

func TestCanonicalCheckpointAndNestedContractRejection(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	_, body := stage(t, s, at)
	if e := s.AcknowledgeReport(ackBytes(t, body, at), at); e != nil {
		t.Fatal(e)
	}
	raw := m.snapshot()
	cases := map[string][]byte{
		"space": append([]byte(" "), raw...), "newline": append(bytes.Clone(raw), '\n'), "extra": append(bytes.Clone(raw), []byte(`{}`)...),
		"duplicate":        bytes.Replace(raw, []byte(`"used":true`), []byte(`"used":true,"used":true`), 1),
		"unknown":          bytes.Replace(raw, []byte(`"used":true`), []byte(`"used":true,"private":"PRIVATE_PROVIDER_TEXT_NOT_FOR_ERRORS"`), 1),
		"case":             bytes.Replace(raw, []byte(`"used":`), []byte(`"Used":`), 1),
		"escaped":          bytes.Replace(raw, []byte(`"used":`), []byte(`"us\u0065d":`), 1),
		"fraction":         bytes.Replace(raw, []byte(`"floor":1`), []byte(`"floor":1.0`), 1),
		"exponent":         bytes.Replace(raw, []byte(`"floor":1`), []byte(`"floor":1e0`), 1),
		"overflow":         bytes.Replace(raw, []byte(`"floor":1`), []byte(`"floor":18446744073709551616`), 1),
		"negative":         bytes.Replace(raw, []byte(`"floor":1`), []byte(`"floor":-1`), 1),
		"duplicate nested": bytes.Replace(raw, []byte(`"status":"recorded"`), []byte(`"status":"recorded","status":"recorded"`), 1),
		"unknown nested":   bytes.Replace(raw, []byte(`"status":"recorded"`), []byte(`"status":"recorded","private":true`), 1),
		"alternative date": bytes.Replace(raw, []byte(`09:00:00Z`), []byte(`09:00:00.000Z`), 1),
		"offset":           bytes.Replace(raw, []byte(`09:00:00Z`), []byte(`09:00:00+00:00`), 1),
		"utf8":             append(bytes.Clone(raw[:len(raw)-1]), 0xff, '}'), "null": []byte(`null`), "array": []byte(`[]`), "missing": nil,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(bad, raw) {
				t.Fatal("ineffective mutation")
			}
			e := ValidateCheckpoint(bad, enableBytes(t))
			if e == nil {
				t.Fatal("noncanonical checkpoint accepted")
			}
			if strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("source text leaked")
			}
		})
	}
	c, _ := decode(raw)
	mutators := map[string]func(*checkpoint){
		"used removed":                func(c *checkpoint) { c.Used = false },
		"version":                     func(c *checkpoint) { c.SchemaVersion = "other" },
		"floor rollback":              func(c *checkpoint) { c.Floor = 0 },
		"unsafe integer":              func(c *checkpoint) { c.Floor = wire.MaxSequence + 1 },
		"lost time":                   func(c *checkpoint) { c.LastCaptureAt = nil },
		"lost attempt":                func(c *checkpoint) { c.Attempt = nil },
		"clock rollback":              func(c *checkpoint) { c.ClockAt = at.Add(-time.Second) },
		"attempt rollback":            func(c *checkpoint) { c.Attempt.Sequence = 0 },
		"attempt timestamp":           func(c *checkpoint) { c.Attempt.CollectedAt = at.Add(time.Second) },
		"status":                      func(c *checkpoint) { c.Attempt.Status = "PRIVATE_PROVIDER_TEXT_NOT_FOR_ERRORS" },
		"raw failure text":            func(c *checkpoint) { c.Attempt.Reason = "PRIVATE_PROVIDER_TEXT_NOT_FOR_ERRORS" },
		"missing enable ack":          func(c *checkpoint) { c.EnableReceipt = nil },
		"empty enable ack":            func(c *checkpoint) { c.EnableReceipt = []byte{} },
		"disable ack without disable": func(c *checkpoint) { c.DisableReceipt = bytes.Clone(c.EnableReceipt) },
		"pending without report":      func(c *checkpoint) { c.Attempt.Status = "pending"; c.Report = nil },
		"report sequence":             func(c *checkpoint) { c.Report.Sequence++ },
		"report time":                 func(c *checkpoint) { c.Report.CollectedAt = c.Report.CollectedAt.Add(time.Second) },
		"report expiry":               func(c *checkpoint) { c.Report.ExpiresAt = c.Report.ExpiresAt.Add(time.Second) },
		"report hash":                 func(c *checkpoint) { c.Report.RequestSHA256 = strings.Repeat("d", 64) },
		"snapshot hash":               func(c *checkpoint) { c.Report.SnapshotSHA256 = strings.Repeat("d", 64) },
		"quality":                     func(c *checkpoint) { c.Report.SourceQuality = "unknown" },
		"dropped fresh report":        func(c *checkpoint) { c.Report.Body = nil },
		"empty report":                func(c *checkpoint) { c.Report.Body = []byte{} },
		"noncanonical report":         func(c *checkpoint) { c.Report.Body = append(c.Report.Body, '\n') },
		"noncanonical receipt":        func(c *checkpoint) { c.Report.Receipt = append(c.Report.Receipt, '\n') },
		"noncanonical control":        func(c *checkpoint) { c.Enable = append(c.Enable, '\n') },
		"recorded without receipt":    func(c *checkpoint) { c.Report.Receipt = nil },
		"future ack":                  func(c *checkpoint) { c.Report.Receipt = ackBytes(t, body, at.Add(time.Second)) },
		"enable ack after capture": func(c *checkpoint) {
			c.EnableReceipt = ackBytes(t, c.Enable, at.Add(time.Second))
			c.ClockAt = at.Add(time.Second)
		},
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			next := clone(c)
			mutate(&next)
			bad, e := json.Marshal(next)
			if e != nil {
				t.Fatal(e)
			}
			if e := ValidateCheckpoint(bad, enableBytes(t)); e == nil {
				t.Fatal("inconsistent checkpoint accepted")
			}
		})
	}
	if e := ValidateCheckpoint(raw, enableBytes(t)); e != nil {
		t.Fatal("good checkpoint rejected", e)
	}
}
func TestExpiredReceiptTombstoneStrictValidation(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	_, raw := stage(t, s, at)
	if e := s.AcknowledgeReport(ackBytes(t, raw, at), at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Inspect(at.Add(wire.Retention)); e != nil {
		t.Fatal(e)
	}
	original, e := decode(m.snapshot())
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*wire.Receipt){
		func(r *wire.Receipt) { r.RequestSHA256 = strings.Repeat("e", 64) }, func(r *wire.Receipt) { r.SnapshotSHA256 = strings.Repeat("e", 64) },
		func(r *wire.Receipt) { r.Binding.SenderBinding = strings.Repeat("e", 64) }, func(r *wire.Receipt) { r.CaptureFloor++ },
		func(r *wire.Receipt) { r.GenerationID = "sample_" + strings.Repeat("e", 32) }, func(r *wire.Receipt) { r.ControlRevision = 2 },
		func(r *wire.Receipt) { r.ReceivedAt = at.Add(wire.Retention) }, func(r *wire.Receipt) { r.CollectedAt = nil },
		func(r *wire.Receipt) { r.Kind = "control" }, func(r *wire.Receipt) { r.Status = "enabled" },
	} {
		c := clone(original)
		var r wire.Receipt
		if json.Unmarshal(c.Report.Receipt, &r) != nil {
			t.Fatal("fixture")
		}
		mutate(&r)
		c.Report.Receipt, _ = json.Marshal(r)
		bad, _ := json.Marshal(c)
		if ValidateCheckpoint(bad, enableBytes(t)) == nil {
			t.Fatal("expired tombstone receipt accepted")
		}
	}
}
func TestCheckpointCapIncludesBase64MaximumSnapshot(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	l := reserve(t, s, at)
	snap := snapshot(l)
	snap.Receipts.Identifiers = make([]string, inventory.MaxReceipts)
	for i := range snap.Receipts.Identifiers {
		snap.Receipts.Identifiers[i] = fmt.Sprintf("r%04d", i)
	}
	raw, _ := json.Marshal(snap)
	remaining := inventory.MaxBytes - len(raw)
	for i := range snap.Receipts.Identifiers {
		n := min(256-len(snap.Receipts.Identifiers[i]), remaining)
		snap.Receipts.Identifiers[i] += strings.Repeat("x", n)
		remaining -= n
	}
	raw, _ = json.Marshal(snap)
	if remaining != 0 || len(raw) != inventory.MaxBytes {
		t.Fatal("max fixture")
	}
	report, e := wire.BuildReport(control(), l.Sequence(), snap)
	if e != nil {
		t.Fatal(e)
	}
	body, e := wire.EncodeReport(report)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Stage(l, body, at); e != nil {
		t.Fatal(e)
	}
	if e := s.AcknowledgeReport(ackBytes(t, body, at), at); e != nil {
		t.Fatal(e)
	}
	off, e := s.Disable(at)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.AcknowledgeControl(ackBytes(t, off, at), at); e != nil {
		t.Fatal(e)
	}
	encoded := m.snapshot()
	if len(encoded) <= len(body)*4/3 || len(encoded) > MaxCheckpointBytes {
		t.Fatal("base64 checkpoint bound", len(encoded), len(body))
	}
	if ValidateCheckpoint(encoded, enableBytes(t)) != nil {
		t.Fatal("maximum checkpoint rejected")
	}
	if _, e := decode(bytes.Repeat([]byte{'x'}, MaxCheckpointBytes+1)); e != ErrBounds {
		t.Fatal(e)
	}
	// Conservative envelope budget: one maximum report, two controls, three
	// receipts and 16 KiB of bounded metadata, including base64 rounding.
	ceiling := 4*((wire.MaxReportBytes+2)/3) + 5*4*((wire.MaxControlBytes+2)/3) + 16*1024
	if ceiling > MaxCheckpointBytes {
		t.Fatal("advertised cap cannot hold bounded representation", ceiling)
	}
}
func TestClockAndSequenceBounds(t *testing.T) {
	at := control().ChangedAt
	for _, bad := range []time.Time{time.Time{}, at.Add(-time.Nanosecond), at.In(time.FixedZone("offset", 3600)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		s, m := fresh(t, true)
		original := m.snapshot()
		if l, e := s.Reserve(bad); e != ErrClock || l != (Lease{}) {
			t.Fatal("bad reserve time", e)
		}
		if _, e := s.Disable(bad); e != ErrClock {
			t.Fatal(e)
		}
		if _, e := Restore(m, enableBytes(t), m.snapshot(), bad); e != ErrClock {
			t.Fatal(e)
		}
		if !bytes.Equal(m.snapshot(), original) {
			t.Fatal("rejected clock mutated state")
		}
	}
	s, m := fresh(t, true)
	if _, e := s.Inspect(at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, m, at.Add(time.Second))
	if _, e := s.Reserve(at); e != ErrClock {
		t.Fatal("reopen clock rollback", e)
	}
	last := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	if _, e := s.Reserve(last); e != ErrBounds {
		t.Fatal("overflow expiry", e)
	}
	c, _ := decode(m.snapshot())
	c.Floor = wire.MaxSequence
	c.LastCaptureAt = &at
	c.Attempt = &attempt{Sequence: c.Floor, CollectedAt: at, Status: "failed", Reason: FailureCollection}
	f := *c.Attempt
	c.LastFailure = &f
	raw, e := encode(c)
	if e != nil {
		t.Fatal(e)
	}
	m.raw = raw
	s.Close()
	s, e = Restore(m, enableBytes(t), raw, at.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if l, e := s.Reserve(at.Add(time.Minute)); e != ErrBounds || l != (Lease{}) {
		t.Fatal("floor overflow", e)
	}
	for _, n := range []uint64{wire.MaxSequence + 1, math.MaxUint64} {
		bad := clone(c)
		bad.Floor = n
		raw, _ := json.Marshal(bad)
		if ValidateCheckpoint(raw, enableBytes(t)) == nil {
			t.Fatal("unsafe floor accepted")
		}
	}
}

func TestReadOnlyCheckpointAdmissionUsesDurableClockFloor(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	if _, e := s.Inspect(at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	raw := m.snapshot()
	for _, tc := range []struct {
		name string
		at   time.Time
		want error
	}{
		{"equal", at.Add(time.Minute), nil},
		{"later", at.Add(2 * time.Minute), nil},
		{"earlier", at, ErrClock},
		{"non-UTC", at.Add(2 * time.Minute).In(time.FixedZone("non-UTC", 3600)), ErrClock},
		{"zero", time.Time{}, ErrClock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := ValidateCheckpointAt(raw, enableBytes(t), tc.at); e != tc.want {
				t.Fatal(e)
			}
			if !bytes.Equal(raw, m.snapshot()) {
				t.Fatal("read-only admission changed checkpoint")
			}
		})
	}
	if e := ValidateCheckpointAt(raw, []byte(`{}`), at.Add(2*time.Minute)); e != ErrConflict {
		t.Fatal("original enable mismatch", e)
	}
}
func TestStagingNeverRewritesBindingOrOriginalCapture(t *testing.T) {
	s, m := fresh(t, true)
	at := control().ChangedAt
	l := reserve(t, s, at)
	before := m.snapshot()
	for _, mutate := range []func(*wire.Report){
		func(r *wire.Report) { r.Binding.SenderBinding = strings.Repeat("d", 64) },
		func(r *wire.Report) { r.CaptureSequence++ },
		func(r *wire.Report) { r.CollectedAt = r.CollectedAt.Add(time.Second) },
		func(r *wire.Report) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) },
		func(r *wire.Report) {
			r.SourceQuality = "full"
			r.Snapshot.Processes.Rows[0].NameQuality = "unavailable"
		},
	} {
		r, _ := wire.DecodeReport(reportBytes(t, l, nil))
		mutate(&r)
		raw, _ := json.Marshal(r)
		if e := s.Stage(l, raw, at); e != ErrInvalid {
			t.Fatal(e)
		}
		if !bytes.Equal(before, m.snapshot()) {
			t.Fatal("rejected stage rewrote reservation")
		}
	}
	if e := s.Stage(Lease{}, reportBytes(t, l, nil), at); e != ErrConflict {
		t.Fatal(e)
	}
	other, _ := fresh(t, true)
	foreign := reserve(t, other, at)
	if e := s.Stage(foreign, reportBytes(t, foreign, nil), at); e != ErrConflict {
		t.Fatal("foreign owner's lease accepted", e)
	}
	if e := s.Stage(l, reportBytes(t, l, nil), at.Add(wire.Retention)); e != ErrExpired {
		t.Fatal(e)
	}
	if e := s.Fail(l, FailureInterrupted, at.Add(wire.Retention)); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, m, at.Add(wire.Retention))
	if e := s.Stage(l, reportBytes(t, l, nil), at.Add(wire.Retention)); e != ErrConflict {
		t.Fatal("lost sequence recaptured", e)
	}
}
func TestInactiveProductionDependenciesAndNoCollectors(t *testing.T) {
	entries, e := os.ReadDir(".")
	if e != nil {
		t.Fatal(e)
	}
	allowed := map[string]bool{"bytes": true, "encoding/json": true, "errors": true, "io": true, "time": true, "unicode/utf8": true, "fmt": true, "sync": true, "localrmm/internal/macosinventorywire": true}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Fatal("active/unreviewed dependency", path)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (strings.HasPrefix(sel.Sel.Name, "Collect") || sel.Sel.Name == "Now" || sel.Sel.Name == "Sleep") {
					t.Fatal("native/clock action introduced", sel.Sel.Name)
				}
			}
			return true
		})
	}
}
func FuzzCheckpointStrictDecode(f *testing.F) {
	enable, _ := wire.EncodeControl(control())
	good, _ := encode(checkpoint{SchemaVersion: CheckpointVersion, Used: true, Enable: enable, ClockAt: control().ChangedAt})
	for _, seed := range [][]byte{nil, []byte(`null`), []byte(`{"used":true,"used":true}`), good} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, e := decode(raw)
		if e != nil {
			switch e {
			case ErrInvalid, ErrBounds, ErrMissing:
				return
			default:
				t.Fatal("unclosed error vocabulary", e)
			}
		}
		b, e := encode(c)
		if e != nil || !bytes.Equal(b, raw) {
			t.Fatal("noncanonical accepted", e)
		}
		enabled, _ := wire.DecodeControl(c.Enable)
		if !c.Used || !enabled.Enabled || wire.ValidateBinding(enabled.Binding) != nil {
			t.Fatal("invalid used checkpoint")
		}
	})
}

func TestEveryRetainedCaptureFollowsOriginalEnableReceipt(t *testing.T) {
	for _, kind := range []string{"report", "expired_report", "failure"} {
		t.Run(kind, func(t *testing.T) {
			s, m := fresh(t, true)
			at := control().ChangedAt
			if kind == "failure" {
				l := reserve(t, s, at)
				if e := s.Fail(l, FailureCollection, at); e != nil {
					t.Fatal(e)
				}
			} else {
				_, raw := stage(t, s, at)
				if e := s.AcknowledgeReport(ackBytes(t, raw, at), at); e != nil {
					t.Fatal(e)
				}
			}
			_ = reserve(t, s, at.Add(time.Minute))
			if kind == "expired_report" {
				if _, e := s.Inspect(at.Add(wire.Retention)); e != nil {
					t.Fatal(e)
				}
			}
			c, e := decode(m.snapshot())
			if e != nil {
				t.Fatal(e)
			}
			// Latest capture is after this forged acknowledgement, but retained earlier
			// report/failure evidence is before it. Checking only LastCaptureAt is unsafe.
			c.EnableReceipt = ackBytes(t, c.Enable, at.Add(30*time.Second))
			bad, _ := json.Marshal(c)
			if e := ValidateCheckpoint(bad, enableBytes(t)); e != ErrInvalid {
				t.Fatal("pre-ack retained capture accepted", e)
			}
		})
	}
	s, m := fresh(t, true)
	at := control().ChangedAt
	l := reserve(t, s, at)
	c, e := decode(m.snapshot())
	if e != nil {
		t.Fatal(e)
	}
	c.LastFailure = &attempt{Sequence: l.Sequence(), CollectedAt: at, Status: "failed", Reason: FailureCollection}
	bad, _ := json.Marshal(c)
	if ValidateCheckpoint(bad, enableBytes(t)) == nil {
		t.Fatal("same reservation both live and previously failed")
	}
}

func TestRetainedReportFailureOrderingAndPendingGate(t *testing.T) {
	at := control().ChangedAt
	// Establish report1, failure2 and live reservation3 through the public API.
	s, m := fresh(t, true)
	_, body := stage(t, s, at)
	if e := s.AcknowledgeReport(ackBytes(t, body, at), at); e != nil {
		t.Fatal(e)
	}
	l := reserve(t, s, at.Add(time.Minute))
	if e := s.Fail(l, FailureCollection, at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	l3 := reserve(t, s, at.Add(2*time.Minute))
	good, e := decode(m.snapshot())
	if e != nil {
		t.Fatal(e)
	}
	mutations := map[string]func(*checkpoint){
		"same failed and reported sequence":          func(c *checkpoint) { c.LastFailure.Sequence = 1; c.LastFailure.CollectedAt = at },
		"later failure before report":                func(c *checkpoint) { c.LastFailure.CollectedAt = at.Add(-time.Nanosecond) },
		"later failure too soon":                     func(c *checkpoint) { c.LastFailure.CollectedAt = at.Add(time.Minute - time.Nanosecond) },
		"report acknowledgement after later failure": func(c *checkpoint) { c.Report.Receipt = ackBytes(t, body, at.Add(90*time.Second)) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := clone(good)
			mutate(&c)
			raw, _ := json.Marshal(c)
			if ValidateCheckpoint(raw, enableBytes(t)) == nil {
				t.Fatal("inconsistent retained evidence accepted")
			}
		})
	}
	body3 := reportBytes(t, l3, nil)
	if e := s.Stage(l3, body3, at.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.AcknowledgeReport(ackBytes(t, body3, at.Add(2*time.Minute)), at.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Disable(at.Add(2 * time.Minute)); e != nil {
		t.Fatal(e)
	}
	terminal, e := decode(m.snapshot())
	if e != nil {
		t.Fatal(e)
	}
	terminal.LastFailure.Status, terminal.LastFailure.Reason = "lost", FailureDisabled
	badTerminal, _ := json.Marshal(terminal)
	if ValidateCheckpoint(badTerminal, enableBytes(t)) == nil {
		t.Fatal("nonfinal terminal-disabled failure accepted")
	}

	// Earlier failures must be earlier in capture time too.
	s, m = fresh(t, true)
	l = reserve(t, s, at)
	if e := s.Fail(l, FailureCollection, at); e != nil {
		t.Fatal(e)
	}
	_, body = stage(t, s, at.Add(time.Minute))
	if e := s.AcknowledgeReport(ackBytes(t, body, at.Add(time.Minute)), at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	_ = reserve(t, s, at.Add(2*time.Minute))
	c, _ := decode(m.snapshot())
	c.LastFailure.CollectedAt = at.Add(time.Second)
	raw, _ := json.Marshal(c)
	if ValidateCheckpoint(raw, enableBytes(t)) == nil {
		t.Fatal("earlier failure paced too close to later report")
	}
	// An unacknowledged report can permit a later reservation only once its
	// original expiry is reached, not merely once a later clock removes its bytes.
	s, m = fresh(t, true)
	_, _ = stage(t, s, at)
	l = reserve(t, s, at.Add(wire.Retention))
	if e := s.Fail(l, FailureCollection, at.Add(wire.Retention)); e != nil {
		t.Fatal(e)
	}
	_ = reserve(t, s, at.Add(wire.Retention+time.Minute))
	good, _ = decode(m.snapshot())
	c = clone(good)
	c.LastFailure.CollectedAt = at.Add(time.Minute)
	raw, _ = json.Marshal(c)
	if ValidateCheckpoint(raw, enableBytes(t)) == nil {
		t.Fatal("failure reserved while older report still pending")
	}
	c = clone(good)
	earlier := at.Add(2 * time.Minute)
	c.LastCaptureAt = &earlier
	c.Attempt.CollectedAt = earlier
	c.LastFailure = nil
	raw, _ = json.Marshal(c)
	if ValidateCheckpoint(raw, enableBytes(t)) == nil {
		t.Fatal("latest reservation bypassed pending expiry")
	}
}
