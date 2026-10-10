package api

import (
	"context"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"sync/atomic"
	"testing"
	"time"
)

type jointWindowsHealthSource struct {
	at                          time.Time
	active                      atomic.Int32
	overlap                     atomic.Bool
	contactReads, capacityReads atomic.Int32
	capacityDone                chan struct{}
}

func (s *jointWindowsHealthSource) Now() time.Time { return s.at }
func (s *jointWindowsHealthSource) enter() {
	if s.active.Add(1) != 1 {
		s.overlap.Store(true)
	}
	time.Sleep(time.Millisecond)
}
func (s *jointWindowsHealthSource) WindowsContactInputs(ctx context.Context, _ time.Time) ([]windowscontact.Input, error) {
	s.enter()
	defer s.active.Add(-1)
	s.contactReads.Add(1)
	return []windowscontact.Input{contactFixtureInput(s.at)}, ctx.Err()
}
func (s *jointWindowsHealthSource) WindowsCapacityInputs(ctx context.Context, _ time.Time) ([]windowscapacity.Input, error) {
	s.enter()
	defer s.active.Add(-1)
	s.capacityReads.Add(1)
	if s.capacityDone != nil {
		close(s.capacityDone)
	}
	return []windowscapacity.Input{capacityFixtureInput(s.at)}, ctx.Err()
}
func TestWindowsHealthProductionSchedulerSerializesSourceAdmission(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	source := &jointWindowsHealthSource{at: time.Now().UTC().Round(0), capacityDone: make(chan struct{})}
	contact, e := newWindowsContactMonitor(o.app.store, source)
	if e != nil {
		t.Fatal(e)
	}
	capacity, e := newWindowsCapacityMonitor(o.app.store, source)
	if e != nil {
		t.Fatal(e)
	}
	o.app.windowsContact = contact
	o.app.windowsCapacity = capacity
	if _, e := o.app.store.ConfigureWindowsCapacity(context.Background(), capacityFixtureInput(source.at), true, 90, 0, source.at); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- o.app.RunWindowsHealthMonitors(ctx, nil, nil) }()
	select {
	case <-source.capacityDone:
	case <-time.After(time.Second):
		t.Fatal("production scheduler did not run both checks")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduler did not join on shutdown")
	}
	if source.overlap.Load() || source.contactReads.Load() != 1 || source.capacityReads.Load() != 1 {
		t.Fatal("independent monitors contended or repeated", source.contactReads.Load(), source.capacityReads.Load())
	}
}
func TestWindowsCapacityDisabledMonitorDoesNotReadSource(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	f.err = context.DeadlineExceeded
	if e := m.evaluate(context.Background()); e != nil || f.reads != 0 {
		t.Fatal("default-off policy used source admission", e, f.reads)
	}
	in := f.inputs[0]
	if _, e := o.app.store.ConfigureWindowsCapacity(context.Background(), in, true, 90, 0, f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := o.app.store.ConfigureWindowsCapacity(context.Background(), in, false, 90, 1, f.now); e != nil {
		t.Fatal(e)
	}
	if e := m.evaluate(context.Background()); e != nil || f.reads != 0 {
		t.Fatal("disabled policy used source admission", e, f.reads)
	}
}
