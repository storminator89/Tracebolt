//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func cachedUpdatesConsentFixture(t *testing.T, m Material) {
	t.Helper()
	raw, e := cachedupdates.EncodeLocalConsent(cachedupdates.LocalConsent{SchemaVersion: cachedupdates.ConsentVersion, ExtensionVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, SenderBinding: m.binding, Acknowledged: true}, m.binding)
	if e != nil || writeCachedUpdatesConsent(m, raw) != nil {
		t.Fatal("consent fixture", e)
	}
}
func TestCachedUpdatesConsentAdminIsQuiescentLocalAndPreservesLedgers(t *testing.T) {
	var network atomic.Int32
	f := integrationFixture(t, "tls", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { network.Add(1); next.ServeHTTP(w, r) })
	})
	m, path := prepareEndpointHandoff(t, f.material)
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ConfigureCachedUpdates(path, "enable", true); e == nil {
		t.Fatal("active sender allowed consent change")
	}
	owner.Close()
	paths := []string{filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(m.config.StateDirectory, "inventory", "ledger.json"), filepath.Join(m.config.StateDirectory, "system", "system-state.json")}
	before := map[string][]byte{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		before[p] = b
	}
	for _, temp := range []string{filepath.Join(m.config.StateDirectory, ".state.tmp"), filepath.Join(m.config.StateDirectory, "system", ".system-state.tmp")} {
		before[temp] = []byte("preserved inert crash temporary")
		if os.WriteFile(temp, before[temp], 0600) != nil {
			t.Fatal("temp")
		}
	}
	for _, mode := range []string{"preview", "enable", "preview", "disable"} {
		result, e := ConfigureCachedUpdates(path, mode, mode == "enable")
		if e != nil || !result.ExistingStatePreserved || result.SchemaVersion != "tracebolt.cached-updates-consent-result.v1" || result.ExtensionVersion != cachedupdates.SchemaVersion || result.Scope != cachedupdates.Scope || result.Disclosure != cachedUpdatesDisclosure {
			t.Fatal(mode, e)
		}
		if mode == "enable" && !result.Enabled || mode == "disable" && result.Enabled {
			t.Fatal("consent result mismatch")
		}
		for p, want := range before {
			got, e := os.ReadFile(p)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal("consent command changed ledger/temp")
			}
		}
	}
	marker := filepath.Join(m.config.StateDirectory, "inventory", ".ledger.tmp")
	markerBytes := []byte("uncertain inventory commit remains held")
	if os.WriteFile(marker, markerBytes, 0600) != nil {
		t.Fatal("uncertainty fixture")
	}
	if _, e = ConfigureCachedUpdates(path, "enable", true); e == nil {
		t.Fatal("inventory uncertainty bypassed")
	}
	got, _ := os.ReadFile(marker)
	if !bytes.Equal(got, markerBytes) {
		t.Fatal("inventory uncertainty marker cleaned")
	}
	for p, want := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("rejected configuration changed state")
		}
	}
	if network.Load() != 0 {
		t.Fatal("local configuration used network")
	}
	if _, e = ConfigureCachedUpdates(path, "enable", false); e == nil {
		t.Fatal("unacknowledged enable")
	}
}
func TestCachedUpdatesConsentMalformedForeignUnsafeAndMissingStateFailClosed(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"acknowledged":true}`), []byte(`not json`)} {
		if os.WriteFile(cachedUpdatesConsentPath(m), raw, 0600) != nil {
			t.Fatal("fixture")
		}
		if _, ok := readCachedUpdatesConsent(m); ok {
			t.Fatal("malformed consent enabled")
		}
	}
	if os.Remove(cachedUpdatesConsentPath(m)) != nil {
		t.Fatal("fixture cleanup")
	}
	target := filepath.Join(filepath.Dir(path), "unrelated")
	if os.WriteFile(target, []byte("preserve"), 0600) != nil || os.Symlink(target, cachedUpdatesConsentPath(m)) != nil {
		t.Fatal("symlink fixture")
	}
	if _, ok := readCachedUpdatesConsent(m); ok {
		t.Fatal("symlink consent enabled")
	}
	if _, e := ConfigureCachedUpdates(path, "enable", true); e == nil {
		t.Fatal("symlink overwritten")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "preserve" {
		t.Fatal("symlink target changed")
	}
	os.Remove(cachedUpdatesConsentPath(m))
	cachedUpdatesConsentFixture(t, m)
	other := m
	other.config.AgentID = "agent_ffeeddccbbaa99887766554433221100"
	other.binding = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, ok := readCachedUpdatesConsent(other); ok {
		t.Fatal("foreign material enabled")
	}
	dir := systemStateDirectory(m.config)
	if os.Rename(dir, dir+"-preserved") != nil {
		t.Fatal("missing-state fixture")
	}
	if _, e := ConfigureCachedUpdates(path, "disable", false); e == nil {
		t.Fatal("missing ledger allowed mutation")
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("missing ledger reinitialized")
	}
}
func TestCachedUpdatesNativeExactRetryAndDisablePreserveSystemFloor(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, disable := range []bool{false, true} {
			t.Run(profile+map[bool]string{false: "/retry", true: "/disable"}[disable], func(t *testing.T) {
				var mu sync.Mutex
				var bodies [][]byte
				var verifier *systemwire.Verifier
				var agent string
				f := integrationFixture(t, profile, func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var raw []byte
						var e error
						if profile == "http-test" {
							v, err := verifier.Verify(r)
							raw, e = v.Body, err
						} else {
							raw, e = io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
						}
						frame, err := systemwire.Decode(raw)
						if e != nil || err != nil {
							t.Error("bad request")
							w.WriteHeader(400)
							return
						}
						mu.Lock()
						bodies = append(bodies, bytes.Clone(raw))
						n := len(bodies)
						mu.Unlock()
						if n == 1 {
							w.WriteHeader(503)
							return
						}
						sum := sha256.Sum256(raw)
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(systemwire.Receipt{SchemaVersion: systemwire.ReceiptVersion, DeviceID: agent, Sequence: frame.Sequence, GenerationID: frame.Snapshot.GenerationID, CollectedAt: frame.Snapshot.CollectedAt, ReceivedAt: time.Now().UTC(), BodyHash: hex.EncodeToString(sum[:])})
					})
				})
				m, _ := prepareEndpointHandoff(t, f.material)
				agent = m.config.AgentID
				if profile == "http-test" {
					var e error
					verifier, e = systemwire.New(systemwire.Config{Origin: m.config.ManagerOrigin, Registry: f.registry})
					if e != nil {
						t.Fatal(e)
					}
				}
				cachedUpdatesConsentFixture(t, m)
				var calls atomic.Int32
				sender, e := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
					return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
				}, func() time.Time { return time.Now().UTC() })
				if e != nil {
					t.Fatal(e)
				}
				defer sender.Close()
				sender.updatesCollect = func(_ context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
					calls.Add(1)
					return cachedupdates.Empty(id, at, cachedupdates.ReasonPermissionDenied), nil
				}
				if _, e = sender.Run(context.Background()); e == nil {
					t.Fatal("unacknowledged report succeeded")
				}
				pending, _ := sender.state.Pending()
				if pending == nil {
					t.Fatal("exact body not retained")
				}
				first := pending.Body()
				if disable {
					if os.Remove(cachedUpdatesConsentPath(m)) != nil {
						t.Fatal("disable fixture")
					}
				}
				if _, e = sender.Run(context.Background()); e != nil {
					t.Fatal(e)
				}
				if calls.Load() != 1 {
					t.Fatal("retry/disable recaptured cached updates")
				}
				mu.Lock()
				defer mu.Unlock()
				if len(bodies) != 2 {
					t.Fatal("delivery count")
				}
				frame, e := systemwire.Decode(bodies[1])
				if e != nil {
					t.Fatal(e)
				}
				if disable {
					if frame.CachedUpdates != nil || frame.Sequence != 2 {
						t.Fatal("disabled pending sent or consumed sequence reused")
					}
				} else if !bytes.Equal(first, bodies[1]) || frame.Sequence != 1 {
					t.Fatal("exact pending bytes changed")
				}
			})
		}
	}
}
func TestCachedUpdatesNativeConsentRemovedDuringCollectionPreventsAnySend(t *testing.T) {
	var requests atomic.Int32
	f := integrationFixture(t, "tls", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
	})
	m, _ := prepareEndpointHandoff(t, f.material)
	cachedUpdatesConsentFixture(t, m)
	sender, e := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
	}, func() time.Time { return time.Now().UTC() })
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	sender.updatesCollect = func(_ context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
		if os.Remove(cachedUpdatesConsentPath(m)) != nil {
			t.Fatal("disable")
		}
		return cachedupdates.Empty(id, at, cachedupdates.ReasonReadFailed), nil
	}
	report, e := sender.Run(context.Background())
	if e != nil || report.Status != "cached_updates_disabled" || requests.Load() != 0 {
		t.Fatal("removed consent still sent", e)
	}
	pending, _ := sender.state.Pending()
	next, _ := sender.state.NextSequence()
	if pending != nil || next != 2 {
		t.Fatal("disabled staged body or floor lost")
	}
}

func TestCachedUpdatesConsentRemovedBeforeSourcePreventsCachedRead(t *testing.T) {
	var updatesCalls atomic.Int32
	f := integrationFixture(t, "tls", func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
			frame, e := systemwire.Decode(raw)
			if e != nil || frame.CachedUpdates != nil {
				t.Error("removed consent still included cached updates")
			}
			w.WriteHeader(503)
		})
	})
	m, _ := prepareEndpointHandoff(t, f.material)
	cachedUpdatesConsentFixture(t, m)
	sender, e := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		if os.Remove(cachedUpdatesConsentPath(m)) != nil {
			t.Fatal("disable fixture")
		}
		return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
	}, func() time.Time { return time.Now().UTC() })
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	sender.updatesCollect = func(_ context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
		updatesCalls.Add(1)
		return cachedupdates.Empty(id, at, cachedupdates.ReasonReadFailed), nil
	}
	if _, e = sender.Run(context.Background()); e == nil || updatesCalls.Load() != 0 {
		t.Fatal("cached update read after consent removal")
	}
}

func TestCachedUpdatesDefaultOffAndStalePendingRequiresFreshCapture(t *testing.T) {
	var requests atomic.Int32
	f := integrationFixture(t, "tls", func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) })
	})
	m, _ := prepareEndpointHandoff(t, f.material)
	now := time.Now().UTC()
	sender, err := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	calls := 0
	sender.updatesCollect = func(_ context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
		calls++
		return cachedupdates.Empty(id, at, cachedupdates.ReasonCacheMissing), nil
	}
	if _, err := sender.Run(context.Background()); err == nil || calls != 0 {
		t.Fatal("default-off collector ran")
	}
	pending, _ := sender.state.Pending()
	frame, err := systemwire.Decode(pending.Body())
	if err != nil || frame.CachedUpdates != nil || frame.SchemaVersion != systemwire.FrameVersion {
		t.Fatal("default frame widened")
	}
	// The supported CLI refuses a running sender. This fixture directly supplies
	// a consent sidecar to isolate the runtime transition without a host action.
	cachedUpdatesConsentFixture(t, m)
	now = now.Add(3 * time.Minute)
	report, err := sender.Run(context.Background())
	if err == nil || !report.DiscardedStale || calls != 1 {
		t.Fatal("stale ordinary frame was reused", err)
	}
	pending, _ = sender.state.Pending()
	frame, err = systemwire.Decode(pending.Body())
	if err != nil || frame.CachedUpdates == nil || frame.Sequence != 2 || !frame.CachedUpdates.CollectedAt.Equal(now) {
		t.Fatal("first cached capture")
	}
	first := pending.Body()
	if _, err := sender.Run(context.Background()); err == nil || calls != 1 {
		t.Fatal("pending exact retry recollected")
	}
	pending, _ = sender.state.Pending()
	if !bytes.Equal(first, pending.Body()) {
		t.Fatal("retry changed exact bytes")
	}
	now = now.Add(3 * time.Minute)
	report, err = sender.Run(context.Background())
	if err == nil || !report.DiscardedStale || calls != 2 || requests.Load() != 4 {
		t.Fatal("stale update frame was reused", err)
	}
	pending, _ = sender.state.Pending()
	frame, err = systemwire.Decode(pending.Body())
	if err != nil || frame.Sequence != 3 || frame.CachedUpdates == nil || !frame.CachedUpdates.CollectedAt.Equal(now) {
		t.Fatal("stale retry refreshed old generation")
	}
}

func TestCachedUpdatesConsentUnsafeModesAndHardlinksFailClosed(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	cachedUpdatesConsentFixture(t, m)
	consent := cachedUpdatesConsentPath(m)
	for _, mode := range []os.FileMode{0644, 0640, 0660} {
		if err := os.Chmod(consent, mode); err != nil {
			t.Fatal(err)
		}
		if _, enabled := readCachedUpdatesConsent(m); enabled {
			t.Fatal("unsafe mode enabled collection")
		}
		if _, err := ConfigureCachedUpdates(path, "enable", true); err == nil {
			t.Fatal("unsafe mode silently replaced")
		}
	}
	if err := os.Chmod(consent, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(path), "consent-hardlink")
	if err := os.Link(consent, target); err != nil {
		t.Fatal(err)
	}
	if _, enabled := readCachedUpdatesConsent(m); enabled {
		t.Fatal("hard-linked consent enabled collection")
	}
	if _, err := ConfigureCachedUpdates(path, "disable", false); err == nil {
		t.Fatal("hard-linked consent removed")
	}
}

func TestCachedUpdatesAndEndpointConsentRemainIndependent(t *testing.T) {
	for _, endpointEnabled := range []bool{false, true} {
		for _, updatesEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("endpoint=%t/updates=%t", endpointEnabled, updatesEnabled), func(t *testing.T) {
				frames := make(chan systemwire.Frame, 1)
				f := integrationFixture(t, "tls", func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						raw, _ := io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
						got, err := systemwire.Decode(raw)
						if err != nil {
							t.Error(err)
						}
						frames <- got
						w.WriteHeader(503)
					})
				})
				m, _ := prepareEndpointHandoff(t, f.material)
				if endpointEnabled {
					consentFixture(t, m)
				}
				if updatesEnabled {
					cachedUpdatesConsentFixture(t, m)
				}
				sender, err := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
					return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
				}, func() time.Time { return time.Now().UTC() })
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				endpointCalls, updateCalls := 0, 0
				sender.identityCollect = func(_ context.Context, id string, at time.Time, _ endpointidentity.LocalConsent, _ string) (endpointidentity.Snapshot, error) {
					endpointCalls++
					return endpointidentity.Empty(id, at, endpointidentity.ReasonPermissionDenied), nil
				}
				sender.updatesCollect = func(_ context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
					updateCalls++
					return cachedupdates.Empty(id, at, cachedupdates.ReasonCacheMissing), nil
				}
				if _, err = sender.Run(context.Background()); err == nil {
					t.Fatal("503 acknowledged")
				}
				var got systemwire.Frame
				select {
				case got = <-frames:
				case <-time.After(5 * time.Second):
					t.Fatal("sender did not reach fixture transport")
				}
				if (endpointCalls == 1) != endpointEnabled || (updateCalls == 1) != updatesEnabled || (got.EndpointIdentity != nil) != endpointEnabled || (got.CachedUpdates != nil) != updatesEnabled {
					t.Fatal("one consent implied another extension")
				}
				expected := systemwire.FrameVersion
				if endpointEnabled {
					expected = systemwire.EndpointFrameVersion
				}
				if updatesEnabled {
					expected = systemwire.CachedUpdatesFrameVersion
				}
				if got.SchemaVersion != expected {
					t.Fatal("unexpected frame variant")
				}
			})
		}
	}
}

func TestCachedUpdatesTimeoutPreservesOrdinarySystemAndEndpointReport(t *testing.T) {
	for _, tc := range []struct {
		name           string
		parentBudget   time.Duration
		sourceExpected bool
	}{
		{"slow-child", 1500 * time.Millisecond, true},
		{"no-extension-budget", 800 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := make(chan systemwire.Frame, 1)
			var agent string
			f := integrationFixture(t, "tls", func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ := io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
					frame, err := systemwire.Decode(raw)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					frames <- frame
					sum := sha256.Sum256(raw)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(systemwire.Receipt{SchemaVersion: systemwire.ReceiptVersion, DeviceID: agent, Sequence: frame.Sequence, GenerationID: frame.Snapshot.GenerationID, CollectedAt: frame.Snapshot.CollectedAt, ReceivedAt: time.Now().UTC(), BodyHash: hex.EncodeToString(sum[:])})
				})
			})
			m, _ := prepareEndpointHandoff(t, f.material)
			agent = m.config.AgentID
			consentFixture(t, m)
			cachedUpdatesConsentFixture(t, m)
			sender, err := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
				return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
			}, func() time.Time { return time.Now().UTC() })
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			sender.identityCollect = func(_ context.Context, id string, at time.Time, _ endpointidentity.LocalConsent, _ string) (endpointidentity.Snapshot, error) {
				snapshot := endpointidentity.Empty(id, at, endpointidentity.ReasonPermissionDenied)
				hostname := "ordinary-endpoint-preserved"
				snapshot.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: &hostname}
				return snapshot, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), tc.parentBudget)
			defer cancel()
			parentDeadline, _ := ctx.Deadline()
			calls := 0
			sender.updatesCollect = func(child context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
				calls++
				deadline, ok := child.Deadline()
				if !ok || time.Until(deadline) > cachedUpdatesAttemptBudget || parentDeadline.Sub(deadline) < cachedUpdatesSendReserve-10*time.Millisecond {
					t.Error("optional collector consumed delivery reserve")
				}
				<-child.Done()
				return cachedupdates.Snapshot{}, child.Err()
			}
			report, err := sender.Run(ctx)
			if err != nil || report.Status != "acknowledged" || ctx.Err() != nil || (calls == 1) != tc.sourceExpected {
				t.Fatalf("optional timeout suppressed ordinary report: report=%+v error=%v parent=%v calls=%d", report, err, ctx.Err(), calls)
			}
			frame := <-frames
			if frame.Sequence != 1 || frame.Snapshot.GenerationID == "" || frame.EndpointIdentity == nil || frame.EndpointIdentity.ReportedHostname.Value == nil || *frame.EndpointIdentity.ReportedHostname.Value != "ordinary-endpoint-preserved" || frame.CachedUpdates == nil || frame.CachedUpdates.Coverage != "unavailable" || frame.CachedUpdates.Reason != cachedupdates.ReasonTimeout {
				t.Fatal("timeout lost base observation or explicit extension failure")
			}
			pending, err := sender.state.Pending()
			if err != nil || pending != nil {
				t.Fatal("acknowledged ordinary report left pending", err)
			}
		})
	}
}

func TestCachedUpdatesParentCancellationRemainsFatal(t *testing.T) {
	var requests atomic.Int32
	f := integrationFixture(t, "tls", func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) })
	})
	m, _ := prepareEndpointHandoff(t, f.material)
	cachedUpdatesConsentFixture(t, m)
	sender, err := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
	}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender.updatesCollect = func(child context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
		cancel()
		<-child.Done()
		return cachedupdates.Empty(id, at, cachedupdates.ReasonTimeout), nil
	}
	if _, err := sender.Run(ctx); !errors.Is(err, context.Canceled) || requests.Load() != 0 {
		t.Fatal("parent cancellation became a transmitted timeout snapshot", err)
	}
	pending, err := sender.state.Pending()
	if err != nil || pending != nil {
		t.Fatal("parent-cancelled attempt was staged", err)
	}
}

func TestCachedUpdatesBudgetCapsAnUnboundedParent(t *testing.T) {
	at := time.Now().UTC()
	generation := "sample_00112233445566778899aabbccddeeff"
	sender := &systemSender{updatesCollect: func(child context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
		deadline, ok := child.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second {
			t.Fatal("unbounded parent did not receive five-second extension budget")
		}
		return cachedupdates.Empty(id, at, cachedupdates.ReasonCacheMissing), nil
	}}
	if _, err := sender.collectCachedUpdates(context.Background(), generation, at, cachedupdates.LocalConsent{}); err != nil {
		t.Fatal(err)
	}
}
