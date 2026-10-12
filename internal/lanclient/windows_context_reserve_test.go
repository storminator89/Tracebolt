//go:build linux

package lanclient

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsupdates"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

// All sources are synthetic and cooperate immediately with cancellation.
// Timing is 1/10 of a 20s outer / 3s reserve / 5s source ceiling:
// four isolated sources need 4s each and the earlier adapter needs 5s.
func TestWindowsContextCooperativeSourcesPreserveSendReserve(t *testing.T) {
	// These are cooperative scheduling limits, not host-performance limits.
	// Crypto and durable sender/manager I/O still execute, but their unscaled
	// wall-clock cost must not consume the synthetic source/send budget.
	synctest.Test(t, testWindowsContextCooperativeSourcesPreserveSendReserve)
}

func testWindowsContextCooperativeSourcesPreserveSendReserve(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	wait := func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	sends := 0
	for attempt := 1; attempt <= 3; attempt++ {
		parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{500 * time.Millisecond, 300 * time.Millisecond})
		report, err := runUsingStateWithSessionContextAuthorityDependencies(ctx, f.material, state, nil, nil, nil, startupWindowsSource,
			func(req *http.Request) (*http.Response, error) {
				deadline, _ := parent.Deadline()
				if parent.Err() != nil || time.Until(deadline) < 300*time.Millisecond {
					t.Fatal("primary send reserve lost")
				}
				sends++
				return startupServe(t, f, req), nil
			},
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			func() (windowsupdates.Consent, bool) { return updatesConsentFixture(f.material), true },
			func(ctx context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
				if e := wait(ctx, 400*time.Millisecond); e != nil {
					return windowsupdates.Snapshot{}, e
				}
				return updatesSourceFixture(ctx, r)
			},
			func() (windowsadapters.Consent, bool) { return adapterConsentFixture(f.material), true },
			func(ctx context.Context, generation, grant string, at time.Time) (windowsadapters.Snapshot, error) {
				if e := wait(ctx, 500*time.Millisecond); e != nil {
					return windowsadapters.Snapshot{}, e
				}
				return adapterSourceFixture(ctx, generation, grant, at)
			},
			func() (windowspatchcontext.Consent, bool) { return patchConsentFixture(f.material), true },
			func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
				if e := wait(ctx, 400*time.Millisecond); e != nil {
					return windowspatchcontext.Snapshot{}, e
				}
				return patchSourceFixture(ctx, r)
			},
			func() (windowssecurity.Consent, bool) { return securityConsentFixture(f.material), true },
			func(ctx context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
				if e := wait(ctx, 400*time.Millisecond); e != nil {
					return windowssecurity.Snapshot{}, e
				}
				return securitySourceFixture(ctx, r)
			},
			func() (windowssessions.Consent, bool) { return sessionConsentFixture(f.material), true },
			func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
				if e := wait(ctx, 400*time.Millisecond); e != nil {
					return windowssessions.Snapshot{}, e
				}
				return sessionSourceFixture(ctx, r)
			}, func() bool { return true })
		cancel()
		next, nextErr := state.NextSequence()
		t.Logf("attempt=%d status=%s error=%v nextSequence=%d totalSends=%d", attempt, report.Status, err, next, sends)
		if attempt == 1 && err != nil {
			t.Fatal("first odd sequence should deliver", err)
		}
		if err != nil || report.Status != "acknowledged" || report.RetriedPending || report.Sequence != uint64(attempt) || nextErr != nil || next != uint64(attempt+1) {
			t.Fatal("cooperative attempt did not advance acknowledged sequence", attempt, report.Status, err, report.Sequence, next, nextErr)
		}
	}
	if sends != 3 {
		t.Fatalf("fairness stalls after precollection: only %d of 3 cooperative attempts delivered", sends)
	}
}
