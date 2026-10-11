//go:build linux

package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsupdates"
	"net/http"
	"testing"
	"time"
)

func TestWindowsPatchContextDualBlockedSourcesStillSendBase(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	u, p := updatesConsentFixture(m), patchConsentFixture(m)
	parent, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 40 * time.Millisecond})
	calls := 0
	var sent frame
	_, e = runUsingStateWithPatchContextDependencies(ctx, m, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
		if parent.Err() != nil {
			t.Fatal("outer deadline consumed")
		}
		if json.NewDecoder(req.Body).Decode(&sent) != nil {
			t.Fatal("frame")
		}
		return nil, errors.New("fixture offline")
	}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowsupdates.Consent, bool) { return u, true }, func(ctx context.Context, _ windowsupdates.Request) (windowsupdates.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowsupdates.Snapshot{}, ctx.Err()
	}, nil, nil, func() (windowspatchcontext.Consent, bool) { return p, true }, func(ctx context.Context, _ windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowspatchcontext.Snapshot{}, ctx.Err()
	})
	if !errors.Is(e, ErrTransport) || calls != 2 || sent.WindowsInventory == nil || sent.WindowsUpdates == nil || sent.WindowsPatchContext == nil || sent.WindowsUpdates.Reason != windowsupdates.ErrBudget.Error() || sent.WindowsPatchContext.History.Reason != windowspatchcontext.ErrBudget.Error() {
		t.Fatal("optional stalls suppressed base", calls, e)
	}
	if !sent.WindowsInventory.CollectedAt.Equal(sent.WindowsPatchContext.CollectedAt) || !sent.WindowsInventory.CollectedAt.Equal(sent.WindowsUpdates.CollectedAt) {
		t.Fatal("fallback refreshed capture")
	}
	pending, e := state.Pending()
	if e != nil || pending == nil {
		t.Fatal("no staged report", e)
	}
}
func TestWindowsPatchContextInsufficientBudgetAndParentCancellation(t *testing.T) {
	r := windowspatchcontext.Request{Consent: patchConsentFixture(windowsMaterialFixture(t, "http-test")), GenerationID: "sample_00000000000000000000000000000000", CollectedAt: time.Now().UTC()}
	called := false
	collect := patchContextWithBudget(func(ctx context.Context, _ windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
		called = true
		<-ctx.Done()
		return windowspatchcontext.Snapshot{}, ctx.Err()
	})
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, e := collect(short, r)
	if e != nil || called || s.History.Reason != windowspatchcontext.ErrBudget.Error() {
		t.Fatal("did not reserve delivery budget", e)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, e = collect(canceled, r); !errors.Is(e, context.Canceled) || called {
		t.Fatal("cancellation downgraded", e)
	}
}
