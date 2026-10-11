//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"testing"
	"time"
)

// All twelve selected scopes are present: ten in the primary pipeline and two
// independent complete-generation bursts after it. Providers and transport are
// fixtures, with the production budget/append/store protocol code unchanged.
func TestWindowsReadAdminCombinedPipelineRetainsReserveAndIndependentGenerations(t *testing.T) {
	for _, starve := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocked-optional", true: "slow-earlier-metadata"}[starve], func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
			if e := f.store.InitializeWindowsFullServices(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e := f.store.InitializeWindowsFullSoftware(context.Background()); e != nil {
				t.Fatal(e)
			}
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			selected := map[string]bool{}
			c := readAdminFixture()
			_, e = applyWindowsCapabilities(c, func(scope string) error { selected[scope] = true; return nil })
			if e != nil {
				t.Fatal(e)
			}
			order := []string{}
			laterCalls := 0
			for attempt := 0; attempt < 2; attempt++ {
				parent, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
				// Test seam only shortens the real 5s/3s limits. It never changes production.
				ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 250 * time.Millisecond})
				var sent frame
				report, e := runUsingStateWithSessionContextAuthorityDependencies(ctx, f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					if parent.Err() != nil {
						t.Fatal("primary deadline consumed")
					}
					deadline, _ := parent.Deadline()
					if time.Until(deadline) < 100*time.Millisecond {
						t.Fatal("primary delivery reserve lost")
					}
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					if len(raw) > MaxFrameBytes {
						t.Fatal("frame budget")
					}
					order = append(order, "primary")
					return startupServe(t, f, req), nil
				}, func() (windowseventhealth.Consent, bool) {
					return eventConsentFixture(f.material), selected[windowseventhealth.Scope]
				}, eventSourceFixture,
					func() (windowsvolumes.Consent, bool) {
						return volumeConsentFixture(f.material), selected[windowsvolumes.Scope]
					}, volumeSourceFixture,
					func() (windowsprocessmetrics.Consent, bool) {
						return processConsentFixture(f.material), selected[windowsprocessmetrics.Scope]
					}, processSourceFixture,
					func() (windowsnetwork.Consent, bool) {
						return networkConsentFixture(f.material), selected[windowsnetwork.Scope]
					}, networkSourceFixture,
					func() (windowsmanaged.ServiceStartupConsent, bool) {
						return serviceStartupConsentFixture(f.material), selected[windowsmanaged.ServiceStartupScope]
					}, serviceStartupSourceFixture,
					nil, nil,
					func() (windowsadapters.Consent, bool) {
						return adapterConsentFixture(f.material), selected[windowsadapters.Scope]
					}, func(ctx context.Context, grant, generation string, at time.Time) (windowsadapters.Snapshot, error) {
						if starve {
							timer := time.NewTimer(560 * time.Millisecond)
							defer timer.Stop()
							select {
							case <-timer.C:
							case <-ctx.Done():
								return windowsadapters.Snapshot{}, ctx.Err()
							}
						}
						return adapterSourceFixture(ctx, grant, generation, at)
					},
					func() (windowspatchcontext.Consent, bool) {
						return patchConsentFixture(f.material), selected[windowspatchcontext.Scope]
					}, func(ctx context.Context, _ windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
						laterCalls++
						<-ctx.Done()
						return windowspatchcontext.Snapshot{}, ctx.Err()
					},
					func() (windowssecurity.Consent, bool) {
						return securityConsentFixture(f.material), selected[windowssecurity.Scope]
					}, func(ctx context.Context, _ windowssecurity.Request) (windowssecurity.Snapshot, error) {
						laterCalls++
						<-ctx.Done()
						return windowssecurity.Snapshot{}, ctx.Err()
					},
					func() (windowssessions.Consent, bool) {
						return sessionConsentFixture(f.material), selected[windowssessions.Scope]
					}, func(ctx context.Context, _ windowssessions.Request) (windowssessions.Snapshot, error) {
						laterCalls++
						<-ctx.Done()
						return windowssessions.Snapshot{}, ctx.Err()
					}, func() bool { return true })
				cancel()
				if e != nil || report.Status != "acknowledged" {
					t.Fatal("primary delivery", report, e)
				}
				if sent.WindowsInventory == nil || sent.WindowsEvents == nil || sent.WindowsVolumes == nil || sent.WindowsProcessMetrics == nil || sent.WindowsNetwork == nil || sent.WindowsServiceStartup == nil || sent.WindowsAdapterContext == nil || sent.WindowsPatchContext == nil || sent.WindowsSecurityPosture == nil || sent.WindowsSessionContext == nil || sent.WindowsUpdates != nil {
					t.Fatal("profile scope mismatch")
				}
				if sent.WindowsPatchContext.History.Reason != windowspatchcontext.ErrBudget.Error() || sent.WindowsSecurityPosture.Defender.Reason != windowssecurity.ErrBudget.Error() || sent.WindowsSessionContext.Sessions.Reason != windowssessions.ErrBudget.Error() {
					t.Fatal("budget failure misrepresented")
				}
				if !sent.WindowsSessionContext.CollectedAt.Equal(sent.WindowsInventory.CollectedAt) || !sent.WindowsSecurityPosture.CollectedAt.Equal(sent.WindowsInventory.CollectedAt) {
					t.Fatal("capture age refreshed")
				}
			}
			if laterCalls != 6 {
				t.Fatal("later source scheduling changed", laterCalls)
			}
			if starve {
				t.Logf("isolated source calls across two slow-adapter attempts: %d; fairness is verified by its own scheduling gate", laterCalls)
			}
			services, e := newFullServicesSender(f.material, fullServicesLocal(t, f.material), func() time.Time { return time.Now().UTC() }, func(context.Context) (windowsfullservices.Capture, error) {
				order = append(order, "services")
				at := time.Now().UTC()
				return windowsfullservices.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: inventedFullServices(2)}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer services.Close()
			services.client = &http.Client{Transport: fullServicesRoundTrip(func(req *http.Request) (*http.Response, error) { return startupServe(t, f, req), nil })}
			software, e := newFullSoftwareSender(f.material, fullSoftwareLocal(t, f.material), func() time.Time { return time.Now().UTC() }, func(context.Context) (windowsfullsoftware.Capture, error) {
				order = append(order, "software")
				at := time.Now().UTC()
				return windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: inventedFullSoftware(2)}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer software.Close()
			software.client = &http.Client{Transport: fullSoftwareRoundTrip(func(req *http.Request) (*http.Response, error) { return startupServe(t, f, req), nil })}
			report := Report{}
			if !selected[windowsfullservices.Scope] || !selected[windowsfullsoftware.Scope] {
				t.Fatal("missing complete grants")
			}
			if e := runWindowsFullServicesAttempt(context.Background(), services, &report); e != nil {
				t.Fatal(e)
			}
			if e := runWindowsFullSoftwareAttempt(context.Background(), software, &report); e != nil {
				t.Fatal(e)
			}
			if report.WindowsFullServicesStatus != "complete" || report.WindowsFullSoftwareStatus != "complete" || len(order) != 4 || order[0] != "primary" || order[1] != "primary" || order[2] != "services" || order[3] != "software" {
				t.Fatal("generation ordering", report, order)
			}
		})
	}
}
