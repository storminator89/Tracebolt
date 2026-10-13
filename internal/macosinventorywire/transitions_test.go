package macosinventorywire

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

func TestTerminalDisableFloorAndRevision(t *testing.T) {
	c := fixtureControl()
	initial := controlBytes(t, c)
	off := disabled(t, 17)
	terminal := controlBytes(t, off)
	for _, floor := range []uint64{0, 16, 17} {
		retry, err := ValidateControlTransition(initial, terminal, floor)
		if err != nil || retry {
			t.Fatal("valid disable rejected", floor, err)
		}
	}
	if _, err := ValidateControlTransition(initial, terminal, 18); err != ErrConflict {
		t.Fatal("disable discarded known consumed floor", err)
	}
	if retry, err := ValidateControlTransition(terminal, terminal, 17); err != nil || !retry {
		t.Fatal("exact disable retry", err)
	}
	if _, err := ValidateControlTransition(terminal, terminal, 18); err != ErrConflict {
		t.Fatal("terminal retry hid floor inconsistency", err)
	}
	if retry, err := ValidateControlTransition(initial, initial, 17); err != nil || !retry {
		t.Fatal("exact initial retry changed an advancing capture floor", err)
	}
	if _, err := ValidateControlTransition(terminal, initial, 17); err != ErrDisabled {
		t.Fatal("reenable accepted", err)
	}
	for _, mutate := range []func(*Control){
		func(c *Control) { c.GrantID = strings.Repeat("d", 32) }, func(c *Control) { c.Binding.SenderBinding = strings.Repeat("d", 64) },
		func(c *Control) { c.GrantRevision = 2 }, func(c *Control) { c.ControlRevision = 3 }, func(c *Control) { c.CaptureFloor = 18 }, func(c *Control) { c.ChangedAt = c.ChangedAt.Add(time.Second) },
	} {
		next := off
		mutate(&next)
		raw, err := EncodeControl(next)
		if err == nil {
			if _, err := ValidateControlTransition(terminal, raw, 17); err == nil {
				t.Fatal("terminal state changed")
			}
		}
	}
	if _, err := ValidateControlTransition(nil, terminal, 0); err == nil {
		t.Fatal("missing used control became fresh")
	}
	if _, err := ValidateControlTransition(initial, terminal, math.MaxUint64); err == nil {
		t.Fatal("overflow floor accepted")
	}
	if _, err := Disable(off, 17, off.ChangedAt); err != ErrDisabled {
		t.Fatal("terminal disable regenerated", err)
	}
	if _, err := Disable(c, 0, c.ChangedAt.Add(-time.Nanosecond)); err == nil {
		t.Fatal("disable time rollback")
	}
	before := fixtureReport(t, 1, c.ChangedAt)
	after := fixtureReport(t, 18, c.ChangedAt.Add(time.Minute))
	for _, r := range []Report{before, after} {
		if ValidateReportBinding(r, off) != ErrDisabled {
			t.Fatal("terminal disable admitted old/new report")
		}
	}
}
func TestCaptureMonotonicityAndExactRetry(t *testing.T) {
	c := fixtureControl()
	first := fixtureReport(t, 1, c.ChangedAt)
	raw := reportBytes(t, first)
	if retry, err := ValidateReportTransition(raw, raw, c); err != nil || !retry {
		t.Fatal("exact report retry", err)
	}
	for _, sequence := range []uint64{2, 19, MaxSequence} {
		next := fixtureReport(t, sequence, c.ChangedAt.Add(time.Minute))
		if retry, err := ValidateReportTransition(raw, reportBytes(t, next), c); err != nil || retry {
			t.Fatal("advancing capture", err)
		}
	}
	for _, at := range []time.Time{c.ChangedAt, c.ChangedAt.Add(time.Minute - time.Nanosecond)} {
		next := fixtureReport(t, 2, at)
		if _, err := ValidateReportTransition(raw, reportBytes(t, next), c); err != ErrConflict {
			t.Fatal("capture cadence accelerated", err)
		}
	}
	second := reportBytes(t, fixtureReport(t, 2, c.ChangedAt.Add(time.Minute)))
	if _, err := ValidateReportTransition(second, raw, c); err != ErrConflict {
		t.Fatal("sequence rollback", err)
	}
	for _, mutate := range []func(*Report){
		func(r *Report) {
			r.Snapshot.Hardware.ModelIdentifier = "Mac15,2"
			r.SnapshotSHA256, _ = SnapshotDigest(r.Snapshot)
		},
		func(r *Report) {
			r.CollectedAt = r.CollectedAt.Add(time.Minute)
			r.ExpiresAt = r.ExpiresAt.Add(time.Minute)
			r.Snapshot.CollectedAt = r.CollectedAt
			r.SnapshotSHA256, _ = SnapshotDigest(r.Snapshot)
		},
	} {
		changed := fixtureReport(t, 1, c.ChangedAt)
		mutate(&changed)
		altered := reportBytes(t, changed)
		if bytes.Equal(raw, altered) {
			t.Fatal("fixture unchanged")
		}
		if _, err := ValidateReportTransition(raw, altered, c); err != ErrConflict {
			t.Fatal("same sequence accepted altered bytes", err)
		}
	}
	if _, err := ValidateReportTransition(raw, second, disabled(t, 2)); err != ErrDisabled {
		t.Fatal("post-disable replay", err)
	}
	if _, err := ValidateReportTransition(nil, raw, c); err == nil {
		t.Fatal("lost used state silently reset")
	}
}
func TestGenerationAndDigestDomains(t *testing.T) {
	c := fixtureControl()
	r := fixtureReport(t, 1, c.ChangedAt)
	id, _ := GenerationID(c.Binding, c.GrantID, 1, 1)
	if id != r.GenerationID {
		t.Fatal("unstable ID")
	}
	other := c.Binding
	other.SenderBinding = strings.Repeat("d", 64)
	for _, args := range []struct {
		binding  Binding
		grant    string
		sequence uint64
	}{{other, c.GrantID, 1}, {c.Binding, strings.Repeat("d", 32), 1}, {c.Binding, c.GrantID, 2}} {
		got, err := GenerationID(args.binding, args.grant, 1, args.sequence)
		if err != nil || got == id {
			t.Fatal("unbound generation", err)
		}
	}
	raw := reportBytes(t, r)
	if r.SnapshotSHA256 == requestDigest(raw) || digest("other-domain", raw) == requestDigest(raw) {
		t.Fatal("digest domains collide")
	}
}
