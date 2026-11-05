package health

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/model"
	"reflect"
	"testing"
	"time"
)

var scheduleAt = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func scheduleCommand(n int, revision uint64, starts time.Time) MaintenanceCommand {
	return MaintenanceCommand{RequestID: fmt.Sprintf("maintenance_%032x", n), ExpectedRevision: revision, Action: "schedule", WindowID: fmt.Sprintf("maintenance_%032x", n), StartsAt: stamp(starts), EndsAt: stamp(starts.Add(15 * time.Minute))}
}
func TestScheduledMaintenanceOriginalWindowCASAndBoundaries(t *testing.T) {
	s := New()
	start := scheduleAt.Add(5 * time.Minute)
	c := scheduleCommand(1, 0, start)
	if e := s.ApplyMaintenance(c, scheduleAt); e != nil {
		t.Fatal(e)
	}
	if s.Version != 2 || s.Schedule.Revision != 1 || s.MaintenanceEnd(start.Add(-time.Nanosecond)) != nil || s.MaintenanceEnd(start) == nil || s.MaintenanceEnd(*c.EndsAt) != nil {
		t.Fatal("fixed boundaries")
	}
	if e := s.ApplyMaintenance(c, scheduleAt.Add(time.Second)); e != nil || s.Schedule.Revision != 1 {
		t.Fatal("exact retry", e)
	}
	altered := c
	altered.EndsAt = stamp(c.EndsAt.Add(time.Minute))
	before, _ := json.Marshal(s)
	if s.ApplyMaintenance(altered, scheduleAt.Add(time.Second)) == nil {
		t.Fatal("altered replay")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("failed mutation")
	}
	wrong := MaintenanceCommand{RequestID: fmt.Sprintf("maintenance_%032x", 2), ExpectedRevision: 0, Action: "cancel", WindowID: c.WindowID}
	if s.ApplyMaintenance(wrong, scheduleAt.Add(time.Second)) == nil {
		t.Fatal("stale revision")
	}
	wrong.ExpectedRevision = 1
	wrong.WindowID = fmt.Sprintf("maintenance_%032x", 3)
	if s.ApplyMaintenance(wrong, scheduleAt.Add(time.Second)) == nil {
		t.Fatal("wrong target")
	}
	wrong.WindowID = c.WindowID
	if e := s.ApplyMaintenance(wrong, scheduleAt.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Schedule.Windows[0].Status(start) != "canceled" || s.MaintenanceEnd(start) != nil {
		t.Fatal("cancel rearmed")
	}
	if s.ApplyMaintenance(c, start) == nil {
		t.Fatal("old create replay after other command")
	}
}
func TestScheduledMaintenanceEarlyEndAndLegacyCannotEndAnotherWindow(t *testing.T) {
	s := New()
	c := scheduleCommand(1, 0, scheduleAt.Add(time.Minute))
	if e := s.ApplyMaintenance(c, scheduleAt); e != nil {
		t.Fatal(e)
	}
	for _, minutes := range []int{0, 15, 60} {
		if s.Maintain(minutes, scheduleAt) == nil || s.Maintain(minutes, *c.StartsAt) == nil {
			t.Fatal("legacy bypass", minutes)
		}
	}
	end := c.StartsAt.Add(time.Second + 123*time.Nanosecond)
	command := MaintenanceCommand{RequestID: fmt.Sprintf("maintenance_%032x", 2), ExpectedRevision: 1, Action: "end", WindowID: c.WindowID}
	if e := s.ApplyMaintenance(command, end); e != nil {
		t.Fatal(e)
	}
	if !s.ScheduledOpeningSuppressed(end.Add(-time.Nanosecond), end) || s.ScheduledOpeningSuppressed(end, end) || s.MaintenanceEnd(end) != nil {
		t.Fatal("early-end precision")
	}
	if e := s.ObserveMaintenance(c.EndsAt.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if s.MaintenanceEnd(*c.StartsAt) != nil || s.ApplyMaintenance(scheduleCommand(3, 2, c.EndsAt.Add(time.Hour)), end) == nil {
		t.Fatal("rollback revived or wrote")
	}
}
func TestScheduledMaintenanceRejectsBoundsAndCapacityWithoutResettingLegacyBytes(t *testing.T) {
	original := New()
	raw, _ := json.Marshal(original)
	var old State
	if json.Unmarshal(raw, &old) != nil || !reflect.DeepEqual(original, old) {
		t.Fatal("legacy changed")
	}
	for _, delta := range []time.Duration{0, 59 * time.Second, 7*24*time.Hour + time.Second} {
		s := New()
		if s.ApplyMaintenance(scheduleCommand(1, 0, scheduleAt.Add(delta)), scheduleAt) == nil {
			t.Fatal("bad lead", delta)
		}
	}
	for _, duration := range []time.Duration{0, 14 * time.Minute, 24 * time.Hour} {
		s := New()
		c := scheduleCommand(1, 0, scheduleAt.Add(time.Minute))
		c.EndsAt = stamp(c.StartsAt.Add(duration))
		if s.ApplyMaintenance(c, scheduleAt) == nil {
			t.Fatal("bad duration")
		}
	}
	s := New()
	now := scheduleAt
	for i := 1; i <= MaxMaintenanceWindows; i++ {
		c := scheduleCommand(i, uint64(i-1), now.Add(time.Minute))
		if e := s.ApplyMaintenance(c, now); e != nil {
			t.Fatal(i, e)
		}
		now = c.EndsAt.Add(time.Second)
		if e := s.ObserveMaintenance(now); e != nil {
			t.Fatal(e)
		}
	}
	if s.ApplyMaintenance(scheduleCommand(99, 64, now.Add(time.Minute)), now) == nil {
		t.Fatal("pruned lifetime history")
	}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	s.Version = 1
	if s.Validate() == nil {
		t.Fatal("old manager marker accepted")
	}
}
func TestScheduledMaintenanceNoEarlySuppressionNoDurationCreditAndRealRecovery(t *testing.T) {
	s := New()
	high := 95.0
	start := scheduleAt.Add(5 * time.Minute)
	s.Evaluate(Input{Authorized: true, ReceivedAt: scheduleAt, Disk: model.Metric{Quality: "healthy", Unit: "%", Value: &high, CollectedAt: scheduleAt}}, scheduleAt)
	bad := *s.Checks[1].BadSince
	if e := s.ApplyMaintenance(scheduleCommand(1, 0, start), scheduleAt.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if !s.Checks[1].BadSince.Equal(bad) {
		t.Fatal("planning reset current confirmation")
	}
	for sec := 30; sec <= 1230; sec += 30 {
		now := scheduleAt.Add(time.Duration(sec) * time.Second)
		s.Evaluate(Input{Authorized: true, ReceivedAt: now, Disk: model.Metric{Quality: "healthy", Unit: "%", Value: &high, CollectedAt: now}}, now)
	}
	if len(s.Incidents) != 1 {
		t.Fatal("existing incident lost", len(s.Incidents))
	}
	low := 70.0
	for sec := 1260; sec <= 1320; sec += 30 {
		now := scheduleAt.Add(time.Duration(sec) * time.Second)
		s.Evaluate(Input{Authorized: true, ReceivedAt: now, Disk: model.Metric{Quality: "healthy", Unit: "%", Value: &low, CollectedAt: now}}, now)
	}
	if s.Incidents[0].ResolvedAt == nil {
		t.Fatal("genuine recovery blocked")
	}
	fresh := New()
	if e := fresh.ApplyMaintenance(scheduleCommand(2, 0, start), scheduleAt); e != nil {
		t.Fatal(e)
	}
	for sec := 300; sec <= 1200; sec += 30 {
		now := scheduleAt.Add(time.Duration(sec) * time.Second)
		fresh.Evaluate(Input{Authorized: true, ReceivedAt: now, Disk: model.Metric{Quality: "healthy", Unit: "%", Value: &high, CollectedAt: now}}, now)
	}
	if len(fresh.Incidents) != 0 {
		t.Fatal("suppressed duration credited")
	}
}

func TestScheduledMaintenanceTerminalRequestIDsAndCorruptStateRejected(t *testing.T) {
	s := New()
	c := scheduleCommand(1, 0, scheduleAt.Add(5*time.Minute))
	if e := s.ApplyMaintenance(c, scheduleAt); e != nil {
		t.Fatal(e)
	}
	close := MaintenanceCommand{RequestID: fmt.Sprintf("maintenance_%032x", 2), ExpectedRevision: 1, Action: "cancel", WindowID: c.WindowID}
	if e := s.ApplyMaintenance(close, scheduleAt.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := s.ApplyMaintenance(scheduleCommand(3, 2, scheduleAt.Add(6*time.Minute)), scheduleAt.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	reused := MaintenanceCommand{RequestID: close.RequestID, ExpectedRevision: 3, Action: "cancel", WindowID: s.Schedule.Windows[1].ID}
	before, _ := json.Marshal(s)
	if s.ApplyMaintenance(reused, scheduleAt.Add(3*time.Second)) == nil {
		t.Fatal("terminal request ID reused")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("rejected reuse mutated")
	}
	for _, change := range []func(*State){func(s *State) { s.Schedule.LastCommand.ExpectedRevision = 0 }, func(s *State) { s.Schedule.Windows[0].ClosedRequestID = "" }, func(s *State) { s.Schedule.Revision++ }, func(s *State) { s.Schedule.Windows[0].ClosedReason = "ended" }} {
		var bad State
		if json.Unmarshal(before, &bad) != nil {
			t.Fatal("fixture")
		}
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("corrupt schedule accepted")
		}
	}
	legacy := New()
	at := scheduleAt.In(time.FixedZone("synthetic", 3600))
	if !legacy.MaintenanceClockValid(at) {
		t.Fatal("legacy trusted local-zone clock rejected")
	}
}
