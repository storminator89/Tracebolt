package windowsmutationfence

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// IntegrationFence exists only in the test build. Production has no injectable
// backend, alternate root, or exported reset/repair seam.
type IntegrationFence struct {
	store       *memoryFence
	Roster      Roster
	now         func() time.Time
	failRelease atomic.Bool
}

func NewIntegrationFence(t *testing.T, p Plan, msi, wua Participant, now func() time.Time) *IntegrationFence {
	t.Helper()
	f := &memoryFence{}
	id, e := beginSetup(context.Background(), p, now().Unix(), f.open)
	if e != nil {
		t.Fatal(e)
	}
	r := Roster{Plan: p, FenceID: id, MSI: msi, WUA: wua}
	if p.Version == ReusablePlanVersion {
		r.Version = ReusableRosterVersion
	}
	if p.Version == BackgroundPlanVersion {
		r.Version = BackgroundRosterVersion
	}
	if p.Version == ReusableWUAPlanVersion {
		r.Version = ReusableWUARosterVersion
	}
	if e = setupChange(context.Background(), r, nil, now().Unix(), f.open); e != nil {
		t.Fatal(e)
	}
	a := testActivation()
	if p.Version == ReusablePlanVersion {
		a.Version = ReusableActivationVersion
	}
	if p.Version == BackgroundPlanVersion {
		a.Version = BackgroundActivationVersion
	}
	if p.Version == ReusableWUAPlanVersion {
		a.Version = ReusableWUAActivationVersion
	}
	if e = setupChange(context.Background(), r, &a, now().Unix(), f.open); e != nil {
		t.Fatal(e)
	}
	return &IntegrationFence{store: f, Roster: r, now: now}
}
func (f *IntegrationFence) Session(t *testing.T, domain string) *Session {
	t.Helper()
	s, e := openSession(context.Background(), f.Roster, domain, f.now, f.open)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// FailNextRelease interrupts only the second transaction of a subsequent
// completion, after the exact terminal evidence has been retained.
func (f *IntegrationFence) FailNextRelease() { f.failRelease.Store(true) }
func (f *IntegrationFence) open(create bool) (storage, error) {
	s, e := f.store.open(create)
	if e != nil {
		return nil, e
	}
	if !create && f.failRelease.Load() {
		raw, e := s.Read(stateFile)
		if e == nil {
			r, e := decode(raw)
			if e == nil && len(r.Entries) > 0 && r.Entries[len(r.Entries)-1].Phase == "completion_recorded" && f.failRelease.CompareAndSwap(true, false) {
				_ = s.Close()
				return nil, ErrUnavailable
			}
		}
	}
	return s, nil
}
