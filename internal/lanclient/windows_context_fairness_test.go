//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A consistently slow earlier adapter must not win every fresh cycle. All
// sources and transport are injected; no host source or network is accessed.
func TestWindowsContextFairnessRetentionRetryAndAuthority(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { state.Close() }()
	calls, adapterCalls := 0, 0
	enabled := true
	forceBudget := true
	sessionConsent := sessionConsentFixture(f.material)
	var bodies [][]byte
	lost := false
	run := func() Report {
		t.Helper()
		parent, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer cancel()
		ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 250 * time.Millisecond})
		report, e := runUsingStateWithSessionContextAuthorityDependencies(ctx, f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
			deadline, _ := parent.Deadline()
			if parent.Err() != nil || time.Until(deadline) < 100*time.Millisecond {
				t.Fatal("primary reserve lost")
			}
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(raw))
			req.Body = io.NopCloser(bytes.NewReader(raw))
			if len(raw) > MaxFrameBytes {
				t.Fatal("frame grew beyond original bound")
			}
			response := startupServe(t, f, req)
			if lost {
				lost = false
				response.Body.Close()
				return nil, errors.New("fixture response lost")
			}
			return response, nil
		}, func() (windowseventhealth.Consent, bool) { return eventConsentFixture(f.material), true }, eventSourceFixture,
			func() (windowsvolumes.Consent, bool) { return volumeConsentFixture(f.material), true }, volumeSourceFixture,
			func() (windowsprocessmetrics.Consent, bool) { return processConsentFixture(f.material), true }, processSourceFixture,
			func() (windowsnetwork.Consent, bool) { return networkConsentFixture(f.material), true }, networkSourceFixture,
			func() (windowsmanaged.ServiceStartupConsent, bool) {
				return serviceStartupConsentFixture(f.material), true
			}, serviceStartupSourceFixture,
			nil, nil,
			func() (windowsadapters.Consent, bool) { return adapterConsentFixture(f.material), true }, func(ctx context.Context, generation, grant string, at time.Time) (windowsadapters.Snapshot, error) {
				adapterCalls++
				// The disabled-context case tests cache authority, not the unchanged
				// earlier-only profile's scheduling. Keep that source immediate.
				if !enabled {
					return adapterSourceFixture(ctx, generation, grant, at)
				}
				timer := time.NewTimer(560 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return windowsadapters.Snapshot{}, ctx.Err()
				}
				return adapterSourceFixture(ctx, generation, grant, at)
			},
			func() (windowspatchcontext.Consent, bool) { return patchConsentFixture(f.material), enabled }, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
				calls++
				if forceBudget {
					return windowspatchcontext.Empty(r, windowspatchcontext.ErrBudget.Error()), nil
				}
				return patchSourceFixture(ctx, r)
			},
			func() (windowssecurity.Consent, bool) { return securityConsentFixture(f.material), enabled }, func(ctx context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
				calls++
				if forceBudget {
					return windowssecurity.Empty(r, windowssecurity.ErrBudget.Error()), nil
				}
				return securitySourceFixture(ctx, r)
			},
			func() (windowssessions.Consent, bool) { return sessionConsent, enabled }, func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
				calls++
				if forceBudget {
					return windowssessions.Empty(r, windowssessions.ErrBudget.Error()), nil
				}
				return sessionSourceFixture(ctx, r)
			}, func() bool { return true })
		if e != nil && !errors.Is(e, ErrTransport) {
			t.Fatal(e)
		}
		return report
	}
	if r := run(); r.Status != "acknowledged" || calls != 3 {
		t.Fatal("first budget-only observation failed", r, calls)
	}
	forceBudget = false
	lost = true
	if r := run(); r.Status != "pending_retained" || calls != 6 || adapterCalls != 2 {
		t.Fatal("isolated group starved", r, calls, adapterCalls)
	}
	before := f.view(t, time.Now().UTC())
	if before.PatchContext == nil || before.SecurityPosture == nil || before.SessionContext == nil || len(before.SessionContext.Sessions.Rows) != 1 {
		t.Fatal("useful observations missing")
	}
	original := before.SessionContext.CollectedAt
	// Reopen both sender and manager before the exact pending retry.
	state.Close()
	f.store.Close()
	f.open(t)
	state, err = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	if r := run(); !r.RetriedPending || r.Status != "acknowledged" || calls != 6 || adapterCalls != 2 || !bytes.Equal(bodies[1], bodies[2]) {
		t.Fatal("retry recaptured or changed bytes", r, calls, adapterCalls)
	}
	after := f.view(t, time.Now().UTC())
	if !after.ReceivedAt.Equal(*before.ReceivedAt) || !after.SessionContext.CollectedAt.Equal(original) {
		t.Fatal("retry refreshed source")
	}
	forceBudget = true
	// Third fresh sequence gives the earlier group priority again. Latest
	// budget failures remain visible beside independently aged useful captures.
	if r := run(); r.Status != "acknowledged" || calls != 9 || adapterCalls != 3 {
		t.Fatal("fresh sequence did not rotate", r, calls, adapterCalls)
	}
	view := f.view(t, time.Now().UTC())
	if view.RetainedContext == nil || view.RetainedContext.SessionContext == nil || view.RetainedContext.SecurityPosture == nil || view.RetainedContext.PatchContext == nil {
		t.Fatal("budget erased useful captures")
	}
	if view.SessionContext.Sessions.Reason != windowssessions.ErrBudget.Error() || view.SecurityPosture.Defender.Reason != windowssecurity.ErrBudget.Error() || view.PatchContext.History.Reason != windowspatchcontext.ErrBudget.Error() {
		t.Fatal("latest source failure hidden")
	}
	if !view.RetainedContext.SessionContext.CollectedAt.Equal(original) || view.RetainedContext.SessionContext.GenerationID != before.SessionContext.GenerationID || view.RetainedContext.SessionContext.GenerationID == view.SessionContext.GenerationID {
		t.Fatal("retained capture rebound or refreshed")
	}
	f.store.Close()
	f.open(t)
	reopened := f.view(t, time.Now().UTC())
	if reopened.RetainedContext == nil || !reopened.RetainedContext.SessionContext.CollectedAt.Equal(original) {
		t.Fatal("retention lost on restart")
	}
	expired, e := view.RecheckAt(original.Add(24 * time.Hour))
	if e != nil || expired.RetainedContext != nil || expired.SessionContext == nil {
		t.Fatal("expiry not based on independent original capture", e)
	}
	// Revoked identities never expose the cache, even before capture expiry.
	revoked := view
	revoked.Status = "revoked"
	revoked, e = revoked.RecheckAt(view.ServerNow)
	if e != nil || revoked.RetainedContext != nil {
		t.Fatal("revoked retained data", e)
	}
	// A failed first observation under a replacement grant cannot inherit
	// the previous grant's useful capture, while unchanged siblings retain it.
	sessionConsent.GrantID = strings.Repeat("4", 32)
	forceBudget = true
	run()
	if got := f.view(t, time.Now().UTC()); got.RetainedContext == nil || got.RetainedContext.SessionContext != nil || got.RetainedContext.SecurityPosture == nil {
		t.Fatal("replacement grant inherited old capture")
	}
	// Disable, then re-enable under a replacement grant. Neither absence nor a
	// new identity-bound grant can revive the previous useful capture.
	enabled = false
	run()
	if got := f.view(t, time.Now().UTC()); got.RetainedContext != nil || got.SessionContext != nil {
		t.Fatal("disabled retained data")
	}
	enabled = true
	sessionConsent.GrantID = strings.Repeat("3", 32)
	run() // Budget-only re-enable cannot revive the previous source.
	if got := f.view(t, time.Now().UTC()); got.RetainedContext != nil || got.SessionContext.GrantID != sessionConsent.GrantID {
		t.Fatal("re-enabled grant revived previous data")
	}
	var last frame
	if json.Unmarshal(bodies[len(bodies)-1], &last) != nil || last.WindowsSessionContext.GrantID != sessionConsent.GrantID {
		t.Fatal("grant binding lost")
	}
}

func TestWindowsContextFairnessRotatesFullBudgetPastSlowSibling(t *testing.T) {
	for _, sourceCount := range []int{3, 6, 9} {
		for turn := 0; turn < sourceCount; turn++ {
			parent, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{40 * time.Millisecond, 50 * time.Millisecond})
			first := -1
			fullBudget := false
			jobs := []func(context.Context) error{}
			for source := 0; source < sourceCount; source++ {
				jobs = append(jobs, func(ctx context.Context) error {
					bounded, done, run := patchOptionalContext(ctx)
					defer done()
					if !run {
						return nil
					}
					if first == -1 {
						first = source
						deadline, _ := bounded.Deadline()
						fullBudget = time.Until(deadline) > 30*time.Millisecond
					}
					<-bounded.Done() // every source consistently exhausts its owned budget
					return nil
				})
			}
			err := collectWindowsContextGroup(ctx, uint64(2+2*turn), jobs)
			deadline, _ := parent.Deadline()
			reserve := time.Until(deadline)
			cancel()
			if err != nil || first != turn || !fullBudget || reserve < 25*time.Millisecond {
				t.Fatal("rotated opportunity or reserve lost", turn, first, fullBudget, reserve, err)
			}
		}
	}

}
