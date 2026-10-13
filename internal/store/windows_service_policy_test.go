package store

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/windowsservicehealth"
)

func TestWindowsServicePolicyGuardSQLWait(t *testing.T) {
	for _, failure := range []string{"valid", "expiry", "session", "source-age"} {
		t.Run(failure, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			in := serviceHealthInput(1, 0, "running")
			conn, err := s.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			waits := s.db.Stats().WaitCount
			var shifted atomic.Bool
			result := make(chan error, 1)
			clock := func() time.Time {
				if shifted.Load() {
					switch failure {
					case "expiry":
						return in.AuthorityUntil
					case "source-age":
						return contactAt.Add(121 * time.Second)
					case "valid":
						return contactAt.Add(time.Second)
					}
				}
				return contactAt
			}
			go func() {
				_, e := s.ConfigureWindowsServiceGuarded(ctx, in, true, []string{"FixtureService"}, 0, clock, func(at time.Time) error {
					if !at.Before(in.AuthorityUntil) || failure == "session" && shifted.Load() {
						return windowsservicehealth.ErrInvalid
					}
					return nil
				})
				result <- e
			}()
			until := time.Now().Add(5 * time.Second)
			for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if s.db.Stats().WaitCount == waits {
				conn.Close()
				t.Fatal("did not wait for SQLite")
			}
			shifted.Store(true)
			conn.Close()
			err = <-result
			if failure == "valid" {
				states, e := s.WindowsServiceStates(ctx)
				state := states[in.DeviceID]
				if err != nil || e != nil || len(states) != 1 || !state.Policy.Enabled || state.PolicyChangedAt == nil || !state.PolicyChangedAt.Equal(contactAt.Add(time.Second)) {
					t.Fatal("valid wait did not commit at actual admission time", err, e, state)
				}
				return
			}
			if err == nil {
				t.Fatal("expired/stale authority committed after SQLite wait")
			}
			states, e := s.WindowsServiceStates(ctx)
			if e != nil || len(states) != 0 {
				t.Fatal("failed after-wait guard wrote state", e)
			}
		})
	}
}
func TestWindowsServicePolicyGuardFinalAndValid(t *testing.T) {
	for _, mode := range []string{"valid", "final-session", "final-age", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			s := contactStore(t)
			in := serviceHealthInput(1, 0, "running")
			clocks, guards := 0, 0
			state, err := s.ConfigureWindowsServiceGuarded(context.Background(), in, true, []string{"FixtureService"}, 0, func() time.Time {
				clocks++
				if clocks >= 4 {
					if mode == "final-age" {
						return contactAt.Add(121 * time.Second)
					}
					if mode == "rollback" {
						return contactAt.Add(-time.Second)
					}
				}
				return contactAt
			}, func(time.Time) error {
				guards++
				if mode == "final-session" && guards == 3 {
					return windowsservicehealth.ErrInvalid
				}
				return nil
			})
			if mode == "valid" {
				if err != nil || state.Policy.Revision != 1 || !state.Policy.Enabled || state.Checks[0].Status != "unknown" {
					t.Fatal(state, err)
				}
				return
			}
			if err == nil {
				t.Fatal("failed final guard committed")
			}
			states, e := s.WindowsServiceStates(context.Background())
			if e != nil || len(states) != 0 {
				t.Fatal("failed final guard wrote state", e)
			}
		})
	}
}
