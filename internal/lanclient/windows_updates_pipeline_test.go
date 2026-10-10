//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func updatesConsentFixture(m Material) windowsupdates.Consent {
	return windowsupdates.Consent{SchemaVersion: windowsupdates.ConsentVersion, Scope: windowsupdates.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("9", 32), Enabled: true}
}
func updatesSourceFixture(_ context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
	return windowsupdates.Snapshot{SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope, GrantID: r.Consent.GrantID, GenerationID: r.GenerationID, CollectedAt: r.CollectedAt, Source: "wua-cache", CacheFreshness: "unknown", Quality: "observed", CountExact: true, ObservedCount: 1, Rows: []windowsupdates.Update{{UpdateID: "12345678-1234-1234-1234-123456789abc", Revision: 4, Title: "Invented update & <script> 日本", KBArticleIDs: []string{"KB1234567"}, Severity: "important", Downloaded: true}}}, nil
}
func runUpdatesOnly(ctx context.Context, m Material, state *lanclientstate.State, base windowsCollector, send func(*http.Request) (*http.Response, error), read func() (windowsupdates.Consent, bool), collect updatesCollector) (Report, error) {
	return runUsingStateWithUpdatesDependencies(ctx, m, state, nil, nil, nil, base, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect)
}

func TestWindowsUpdatesAll64SelectionsBothTransportAdmissions(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for bits := 0; bits < 64; bits++ {
			t.Run(fmt.Sprintf("%s/%d", transport, bits), func(t *testing.T) {
				f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
				state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				ec, vc, pc, nc, sc, uc := eventConsentFixture(f.material), volumeConsentFixture(f.material), processConsentFixture(f.material), networkConsentFixture(f.material), serviceStartupConsentFixture(f.material), updatesConsentFixture(f.material)
				ec.Enabled, vc.Enabled, pc.Enabled, nc.Enabled, sc.Enabled, uc.Enabled = bits&1 != 0, bits&2 != 0, bits&4 != 0, bits&8 != 0, bits&16 != 0, bits&32 != 0
				calls := 0
				var sent frame
				_, err = runUsingStateWithUpdatesDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					return startupServe(t, f, req), nil
				}, func() (windowseventhealth.Consent, bool) { return ec, ec.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, vc.Enabled }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, pc.Enabled }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, nc.Enabled }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, sc.Enabled }, serviceStartupSourceFixture, func() (windowsupdates.Consent, bool) { return uc, uc.Enabled }, func(ctx context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
					calls++
					return updatesSourceFixture(ctx, r)
				})
				if err != nil {
					t.Fatal(err)
				}
				v := f.view(t, time.Now().UTC())
				if (v.Events != nil) != ec.Enabled || (v.Volumes != nil) != vc.Enabled || (v.ProcessMetrics != nil) != pc.Enabled || (v.Network != nil) != nc.Enabled || (v.ServiceStartup != nil) != sc.Enabled || (v.Updates != nil) != uc.Enabled {
					t.Fatal("scope isolation")
				}
				want := FrameWindowsInventoryVersion
				for _, entry := range []struct {
					on      bool
					version string
				}{{ec.Enabled, FrameWindowsEventsVersion}, {vc.Enabled, FrameWindowsCapabilitiesVersion}, {pc.Enabled, FrameWindowsProcessMetricsVersion}, {nc.Enabled, FrameWindowsNetworkVersion}, {sc.Enabled, FrameWindowsServiceStartupVersion}, {uc.Enabled, FrameWindowsUpdatesVersion}} {
					if entry.on {
						want = entry.version
					}
				}
				if sent.SchemaVersion != want || calls != bits>>5 {
					t.Fatal("default-off/version changed", sent.SchemaVersion, calls)
				}
				if uc.Enabled {
					for _, p := range sent.Observation.Privacy {
						if strings.Contains(p, "or updates are included.") {
							t.Fatal("contradictory update privacy disclosure")
						}
					}
				}
				if uc.Enabled && (v.Updates.CacheFreshness != "unknown" || !v.Updates.CollectedAt.Equal(v.Snapshot.CollectedAt) || !reflect.DeepEqual(v.Updates.Rows, sent.WindowsUpdates.Rows)) {
					t.Fatal("update capture/metadata changed")
				}
				basic, err := f.store.LatestObservations(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(basic)
				for _, private := range []string{"windowsUpdates", "kbArticleIds", "Invented update"} {
					if bytes.Contains(raw, []byte(private)) {
						t.Fatal("update data entered basic output")
					}
				}
			})
		}
	}
}

func TestWindowsUpdatesExactRetryRestartCaptureAndDisable(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
			state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { state.Close() }()
			c := updatesConsentFixture(f.material)
			calls := 0
			budget := false
			var bodies [][]byte
			var receipts []lanstore.Receipt
			run := func() (Report, error) {
				return runUpdatesOnly(context.Background(), f.material, state, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					bodies = append(bodies, bytes.Clone(raw))
					req.Body = io.NopCloser(bytes.NewReader(raw))
					resp := startupServe(t, f, req)
					reply, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var receipt lanstore.Receipt
					json.Unmarshal(reply, &receipt)
					receipts = append(receipts, receipt)
					if len(bodies) == 1 {
						return nil, errors.New("fixture response loss")
					}
					resp.Body = io.NopCloser(bytes.NewReader(reply))
					return resp, nil
				}, func() (windowsupdates.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
					calls++
					s, err := updatesSourceFixture(ctx, r)
					if budget {
						s.Quality, s.Reason, s.CountExact, s.ObservedCount, s.Rows = "unavailable", windowsupdates.ErrBudget.Error(), false, 0, []windowsupdates.Update{}
					}
					return s, err
				})
			}
			if _, err = run(); !errors.Is(err, ErrTransport) {
				t.Fatal(err)
			}
			before := f.view(t, time.Now().UTC())
			if before.Updates == nil {
				t.Fatal("missing updates")
			}
			state.Close()
			f.store.Close()
			f.open(t)
			state, err = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
			if err != nil {
				t.Fatal(err)
			}
			report, err := run()
			if err != nil || !report.Duplicate || calls != 1 || !bytes.Equal(bodies[0], bodies[1]) || !receipts[0].ReceivedAt.Equal(receipts[1].ReceivedAt) {
				t.Fatal("exact retry lost", err)
			}
			if !f.view(t, time.Now().UTC()).Updates.CollectedAt.Equal(before.Updates.CollectedAt) {
				t.Fatal("retry refreshed capture")
			}
			budget = true
			if _, err = run(); err != nil {
				t.Fatal(err)
			}
			v := f.view(t, time.Now().UTC())
			if v.Updates == nil || v.Updates.Quality != "unavailable" || v.Updates.Reason != windowsupdates.ErrBudget.Error() {
				t.Fatal("timeout failed ordinary inventory")
			}
			c.Enabled = false
			if _, err = run(); err != nil {
				t.Fatal(err)
			}
			if f.view(t, time.Now().UTC()).Updates != nil || calls != 2 {
				t.Fatal("disable recollected or retained generation")
			}
		})
	}
}

func TestWindowsUpdatesPendingReplacementAndThreeRevocationChecks(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	c := updatesConsentFixture(m)
	calls := 0
	var sent frame
	send := func(req *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(req.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	run := func(read func() (windowsupdates.Consent, bool), collect updatesCollector) (Report, error) {
		return runUpdatesOnly(context.Background(), m, state, startupWindowsSource, send, read, collect)
	}
	read := func() (windowsupdates.Consent, bool) { return c, c.Enabled }
	run(read, updatesSourceFixture)
	p, _ := state.Pending()
	if p == nil || sent.WindowsUpdates == nil {
		t.Fatal("missing pending")
	}
	first := p.Sequence
	c.GrantID = strings.Repeat("8", 32)
	r, _ := run(read, updatesSourceFixture)
	if !r.DiscardedUnconsented || sent.Sequence <= first || sent.WindowsUpdates.GrantID != c.GrantID {
		t.Fatal("replacement replayed")
	}
	c.Enabled = false
	r, _ = run(read, func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error) {
		t.Fatal("disabled read")
		return windowsupdates.Snapshot{}, nil
	})
	if !r.DiscardedUnconsented || sent.WindowsUpdates != nil || sent.SchemaVersion != FrameWindowsInventoryVersion {
		t.Fatal("revoked pending sent")
	}
	p, _ = state.Pending()
	state.Discard(p.Digest)
	c.Enabled = true
	_, err = run(read, func(ctx context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
		s, e := updatesSourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if !errors.Is(err, ErrState) || calls != 3 {
		t.Fatal("postcapture revocation", err, calls)
	}
	c.Enabled = true
	reads := 0
	_, err = run(func() (windowsupdates.Consent, bool) { reads++; return c, reads < 4 }, updatesSourceFixture)
	if !errors.Is(err, ErrState) || reads != 4 || calls != 3 {
		t.Fatal("presend revocation", err, reads, calls)
	}
	p, _ = state.Pending()
	if p == nil {
		t.Fatal("sequence reset")
	}
	state.Discard(p.Digest)
	c.Enabled = true
	reads = 0
	_, err = run(func() (windowsupdates.Consent, bool) { reads++; return c, reads < 2 }, func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error) {
		t.Fatal("revoked before source")
		return windowsupdates.Snapshot{}, nil
	})
	if !errors.Is(err, ErrState) || reads != 2 {
		t.Fatal("pre-source revocation", err, reads)
	}
}

func TestWindowsUpdatesAbsentKeepsOldPendingBytes(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f, raw, err := collectWindowsFrame(context.Background(), m.config, 1, startupWindowsSource)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err = appendWindowsServiceStartup(context.Background(), m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = state.Stage(1, raw); err != nil {
		t.Fatal(err)
	}
	for _, newlyEnabled := range []bool{false, true} {
		_, err = runUsingStateWithUpdatesDependencies(context.Background(), m, state, nil, nil, nil, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
			t.Fatal("old pending recollected")
			return windowsmanaged.Snapshot{}, model.Device{}, nil
		}, func(req *http.Request) (*http.Response, error) {
			got, _ := io.ReadAll(req.Body)
			if !bytes.Equal(got, raw) {
				t.Fatal("old pending bytes rewritten")
			}
			return nil, errors.New("fixture")
		}, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowsmanaged.ServiceStartupConsent, bool) { return serviceStartupConsentFixture(m), true }, nil, func() (windowsupdates.Consent, bool) { return updatesConsentFixture(m), newlyEnabled }, func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error) {
			t.Fatal("absent scope collected")
			return windowsupdates.Snapshot{}, nil
		})
		if !errors.Is(err, ErrTransport) {
			t.Fatal(err)
		}
	}
}

func TestWindowsUpdatesMaximalFramePreservesSiblingBindings(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := withProcessMetricSelfPID(context.Background(), 7)
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		r := syntheticWindowsReport(time.Now().UTC())
		r.Processes.Rows = []windowsinventory.Process{}
		for i := 1; i <= 128; i++ {
			r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: uint32(i), Name: strings.Repeat("p", 250), Threads: 1})
		}
		r.Services.Quality, r.Services.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Services.Rows = append(r.Services.Rows, windowsinventory.Service{Name: fmt.Sprintf("Service%03d", i) + strings.Repeat("x", 60), DisplayName: "Fixture", State: "running", PID: 7})
		}
		r.Software.Quality, r.Software.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("s", 240), Version: "1", Publisher: "Fixture", RegistryView: "64"})
		}
		return windowsmanaged.FromReport(r, g)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Observation.Privacy = []string{strings.Repeat("a", 3400), strings.Repeat("b", 3400), strings.Repeat("c", 3400)}
	f, _, err = appendWindowsEvents(ctx, m, f, eventConsentFixture(m), eventSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsVolumes(ctx, m, f, volumeConsentFixture(m), volumeSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), processSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), networkSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(f.WindowsInventory)
	counts := []uint32{f.WindowsVolumes.ObservedCount, f.WindowsProcessMetrics.ObservedCount, f.WindowsNetwork.ObservedCount, f.WindowsServiceStartup.RequestedCount}
	beforeRows := len(f.WindowsVolumes.Rows) + len(f.WindowsProcessMetrics.Rows) + len(f.WindowsNetwork.Rows) + len(f.WindowsServiceStartup.Rows)
	startupDigest := f.WindowsServiceStartup.ServicesSHA256
	captures := []time.Time{f.WindowsEvents.CollectedAt, f.WindowsVolumes.CollectedAt, f.WindowsProcessMetrics.CollectedAt, f.WindowsNetwork.CollectedAt, f.WindowsServiceStartup.CollectedAt}
	original, err := updatesSourceFixture(context.Background(), windowsupdates.Request{Consent: updatesConsentFixture(m), SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
	if err != nil {
		t.Fatal(err)
	}
	original.Rows = []windowsupdates.Update{}
	original.ObservedCount = 64
	original.Truncated = true
	for i := 0; i < 40; i++ {
		original.Rows = append(original.Rows, windowsupdates.Update{UpdateID: fmt.Sprintf("12345678-1234-1234-1234-%012x", i), Revision: 1, Title: strings.Repeat("界", 85), KBArticleIDs: []string{"KB1234567", "KB2345678", "KB3456789", "KB4567890", "KB5678901", "KB6789012", "KB7890123", "KB8901234"}, Severity: "important"})
	}
	original, err = windowsupdates.FitBudget(original, windowsupdates.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsUpdates(ctx, m, f, updatesConsentFixture(m), func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error) { return original, nil })
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.WindowsInventory)
	if !bytes.Equal(base, after) || len(raw) > MaxFrameBytes || f.WindowsServiceStartup.ServicesSHA256 != startupDigest || !f.WindowsUpdates.CollectedAt.Equal(original.CollectedAt) || f.WindowsUpdates.ObservedCount != 64 || f.WindowsUpdates.CacheFreshness != "unknown" {
		t.Fatal("maximal update frame lost bound truth")
	}
	got := []time.Time{f.WindowsEvents.CollectedAt, f.WindowsVolumes.CollectedAt, f.WindowsProcessMetrics.CollectedAt, f.WindowsNetwork.CollectedAt, f.WindowsServiceStartup.CollectedAt}
	if !reflect.DeepEqual(captures, got) {
		t.Fatal("sibling capture changed")
	}
	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	gotCounts := []uint32{f.WindowsVolumes.ObservedCount, f.WindowsProcessMetrics.ObservedCount, f.WindowsNetwork.ObservedCount, f.WindowsServiceStartup.RequestedCount}
	if !reflect.DeepEqual(counts, gotCounts) {
		t.Fatal("pressure changed sibling counts")
	}
	afterRows := len(f.WindowsVolumes.Rows) + len(f.WindowsProcessMetrics.Rows) + len(f.WindowsNetwork.Rows) + len(f.WindowsServiceStartup.Rows)
	if afterRows >= beforeRows || len(f.WindowsUpdates.Rows) >= len(original.Rows) {
		t.Fatal("fixture did not force both sibling and update trimming", beforeRows, afterRows, len(original.Rows), len(f.WindowsUpdates.Rows))
	}
	self := false
	for _, row := range f.WindowsProcessMetrics.Rows {
		if row.PID == 7 {
			self = true
		}
	}
	if !self {
		t.Fatal("update trim evicted protected self metric")
	}
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if _, err = state.Stage(f.Sequence, raw); err != nil {
		t.Fatal(err)
	}
	_, err = runUsingStateWithUpdatesDependencies(context.Background(), m, state, nil, nil, nil, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
		t.Fatal("fitted pending recollected")
		return windowsmanaged.Snapshot{}, model.Device{}, nil
	}, func(req *http.Request) (*http.Response, error) {
		got, _ := io.ReadAll(req.Body)
		if !bytes.Equal(got, raw) {
			t.Fatal("pressure retry refitted bytes")
		}
		return nil, errors.New("fixture offline")
	}, func() (windowseventhealth.Consent, bool) { return eventConsentFixture(m), true }, nil, func() (windowsvolumes.Consent, bool) { return volumeConsentFixture(m), true }, nil, func() (windowsprocessmetrics.Consent, bool) { return processConsentFixture(m), true }, nil, func() (windowsnetwork.Consent, bool) { return networkConsentFixture(m), true }, nil, func() (windowsmanaged.ServiceStartupConsent, bool) { return serviceStartupConsentFixture(m), true }, nil, func() (windowsupdates.Consent, bool) { return updatesConsentFixture(m), true }, nil)
	if !errors.Is(err, ErrTransport) {
		t.Fatal("pressure retry", err)
	}
}
func TestWindowsUpdatesRejectsCollectorBindingAndCaptureRewrite(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	for _, kind := range []string{"generation", "grant", "capture", "future", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f, _, err := collectWindowsFrame(ctx, m.config, 1, startupWindowsSource)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = appendWindowsUpdates(ctx, m, f, updatesConsentFixture(m), func(ctx context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
				s, e := updatesSourceFixture(ctx, r)
				switch kind {
				case "generation":
					s.GenerationID = "sample_" + strings.Repeat("0", 32)
				case "grant":
					s.GrantID = strings.Repeat("1", 32)
				case "capture":
					s.CollectedAt = s.CollectedAt.Add(-time.Nanosecond)
				case "future":
					s.CollectedAt = s.CollectedAt.Add(time.Hour)
				case "canceled":
					cancel()
				}
				return s, e
			})
			if err == nil {
				t.Fatal("collector binding accepted")
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("caller cancellation hidden")
			}
		})
	}
}

func TestWindowsUpdatesDoesNotRelaxObservationEnvelope(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, startupWindowsSource)
	if err != nil {
		t.Fatal(err)
	}
	f.Observation.Privacy = []string{"", "", "", ""}
	empty, _ := json.Marshal(f.Observation)
	for i := range f.Observation.Privacy {
		f.Observation.Privacy[i] = strings.Repeat("p", (MaxWindowsObservationBytes-len(empty)-16)/4)
	}
	original, _ := json.Marshal(f)
	if _, err = decodeFrameForConfig(original, f.Sequence, m.config); err != nil {
		t.Fatal("invalid observation-pressure fixture", err)
	}
	if _, _, err = appendWindowsUpdates(context.Background(), m, f, updatesConsentFixture(m), updatesSourceFixture); err == nil {
		t.Fatal("expanded 16KiB observation budget")
	}
	after, _ := json.Marshal(f)
	if !bytes.Equal(original, after) {
		t.Fatal("rejected fit mutated original observation")
	}
}
