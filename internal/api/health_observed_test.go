package api

import (
	"context"
	"errors"
	"localrmm/internal/health"
	"testing"
	"time"
)

type observedHealthSource struct {
	at     time.Time
	err    error
	reads  int
	onRead func()
}

func (s *observedHealthSource) Now() time.Time { return s.at }
func (s *observedHealthSource) HealthInputs(context.Context, map[string][]string, time.Time) ([]health.Input, error) {
	s.reads++
	s.at = s.at.Add(time.Second)
	if s.onRead != nil {
		s.onRead()
	}
	return nil, s.err
}

func TestHealthMonitorObservedCompletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		cancel bool
	}{
		{name: "success"},
		{name: "failure", err: context.DeadlineExceeded},
		{name: "shutdown", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := setup(t)
			source := &observedHealthSource{at: time.Now(), err: tc.err}
			app.health = &healthMonitor{store: app.store, source: source}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if tc.cancel {
				source.onRead = cancel
			}
			calls := 0
			if err := app.RunHealthMonitorObserved(ctx, nil, func(at time.Time, err error) {
				calls++
				if source.reads != 1 || !at.Equal(source.at) || !errors.Is(err, tc.err) {
					t.Error("observer did not report actual completed evaluation", at, err)
				}
				cancel()
			}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if tc.cancel {
				want = 0
			}
			if calls != want {
				t.Fatalf("observer called %d times, want %d", calls, want)
			}
		})
	}
}

func TestWindowsHealthMonitorsObservedCompletion(t *testing.T) {
	contactFailure := errors.New("contact fixture failure")
	capacityFailure := errors.New("capacity fixture failure")
	for _, tc := range []struct {
		name                    string
		contactErr, capacityErr error
		contact, capacity       bool
		cancel                  bool
	}{
		{name: "success", contact: true, capacity: true},
		{name: "contact failure", contact: true, capacity: true, contactErr: contactFailure},
		{name: "capacity failure", contact: true, capacity: true, capacityErr: capacityFailure},
		{name: "both failures", contact: true, capacity: true, contactErr: contactFailure, capacityErr: capacityFailure},
		{name: "contact only", contact: true},
		{name: "capacity only", capacity: true},
		{name: "shutdown", contact: true, capacity: true, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, contact := installContactFixture(t, o)
			_, capacity := installCapacityFixture(t, o)
			contact.err, capacity.err = tc.contactErr, tc.capacityErr
			if !tc.contact {
				o.app.windowsContact = nil
			}
			if !tc.capacity {
				o.app.windowsCapacity = nil
			} else if _, err := o.app.store.ConfigureWindowsCapacity(context.Background(), capacity.inputs[0], true, 90, 0, capacity.now); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var lastRead time.Time
			onRead := func(int) { lastRead = time.Now() }
			contact.onRead, capacity.onRead = onRead, onRead
			if tc.cancel {
				capacity.onRead = func(int) { cancel() }
			}
			calls := 0
			if err := o.app.RunWindowsHealthMonitorsObserved(ctx, nil, nil, func(at time.Time, err error) {
				calls++
				if tc.contact && contact.reads != 1 || tc.capacity && capacity.reads != 1 || at.Before(lastRead) || at.After(time.Now()) {
					t.Error("observer ran before configured evaluations completed")
				}
				if tc.contactErr == nil && tc.capacityErr == nil {
					if err != nil {
						t.Error("successful evaluation reported error", err)
					}
				} else if tc.contactErr != nil && !errors.Is(err, tc.contactErr) || tc.capacityErr != nil && !errors.Is(err, tc.capacityErr) {
					t.Error("observer lost evaluation failure", err)
				}
				cancel()
			}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if tc.cancel {
				want = 0
			}
			if calls != want {
				t.Fatalf("observer called %d times, want %d", calls, want)
			}
		})
	}
}

func TestHealthObserversIgnoreUnconfiguredMonitors(t *testing.T) {
	app := &Server{}
	observed := func(time.Time, error) { t.Error("unconfigured monitor reported evaluation") }
	if err := app.RunHealthMonitorObserved(context.Background(), nil, observed); err != nil {
		t.Fatal(err)
	}
	if err := app.RunWindowsHealthMonitorsObserved(context.Background(), nil, nil, observed); err != nil {
		t.Fatal(err)
	}
}
