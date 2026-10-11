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
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func adapterConsentFixture(m Material) windowsadapters.Consent {
	return windowsadapters.Consent{SchemaVersion: windowsadapters.ConsentVersion, Scope: windowsadapters.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("8", 32), Enabled: true}
}
func adapterSourceFixture(_ context.Context, g, grant string, at time.Time) (windowsadapters.Snapshot, error) {
	tx, rx := uint64(1000000000), uint64(100000000)
	return windowsadapters.Snapshot{SchemaVersion: windowsadapters.SchemaVersion, Scope: windowsadapters.Scope, GrantID: grant, GenerationID: g, CollectedAt: at, Quality: "observed", CountExact: true, ObservedCount: 1, Rows: []windowsadapters.Adapter{{IfIndex: 7, IPv6IfIndex: 7, Name: "Invented adapter & <tag> 日本", State: "down", TxLinkBps: &tx, TxQuality: "observed", RxLinkBps: &rx, RxQuality: "observed", DNSServers: windowsadapters.AddressList{Quality: "observed", Addresses: []string{"192.0.2.53", "2001:db8::53"}}, Gateways: windowsadapters.AddressList{Quality: "observed", Addresses: []string{"fe80::1%7"}}}}}, nil
}
func runAdaptersOnly(ctx context.Context, m Material, state *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowsadapters.Consent, bool), collect adapterContextCollector) (Report, error) {
	return runUsingStateWithAdapterContextDependencies(ctx, m, state, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect)
}
func TestWindowsAdapterContextEndToEndSelectionsAndAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, selection := range []string{"off", "adapter-only", "all"} {
			t.Run(transport+"/"+selection, func(t *testing.T) {
				f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
				state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
				if e != nil {
					t.Fatal(e)
				}
				defer state.Close()
				ec, vc, pc, nc, sc, uc, ac := eventConsentFixture(f.material), volumeConsentFixture(f.material), processConsentFixture(f.material), networkConsentFixture(f.material), serviceStartupConsentFixture(f.material), updatesConsentFixture(f.material), adapterConsentFixture(f.material)
				all := selection == "all"
				ac.Enabled = selection != "off"
				calls := 0
				var sent frame
				_, e = runUsingStateWithAdapterContextDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					return startupServe(t, f, req), nil
				},
					func() (windowseventhealth.Consent, bool) { return ec, all }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, all }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, all }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, all }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, all }, serviceStartupSourceFixture, func() (windowsupdates.Consent, bool) { return uc, all }, updatesSourceFixture, func() (windowsadapters.Consent, bool) { return ac, ac.Enabled }, func(ctx context.Context, g, grant string, at time.Time) (windowsadapters.Snapshot, error) {
						calls++
						return adapterSourceFixture(ctx, g, grant, at)
					})
				if e != nil {
					t.Fatal(e)
				}
				v := f.view(t, time.Now().UTC())
				if (v.AdapterContext != nil) != ac.Enabled || calls != map[bool]int{true: 1, false: 0}[ac.Enabled] {
					t.Fatal("default off failed")
				}
				if !ac.Enabled {
					if sent.SchemaVersion != FrameWindowsInventoryVersion {
						t.Fatal("old frame promoted")
					}
					return
				}
				if sent.SchemaVersion != FrameWindowsAdapterContextVersion || v.AdapterContext.Rows[0].State != "down" || !v.AdapterContext.CollectedAt.Equal(v.Snapshot.CollectedAt) {
					t.Fatal("lost admitted source")
				}
				if (v.Network != nil) != all || (v.Updates != nil) != all || (v.ServiceStartup != nil) != all {
					t.Fatal("other grants altered")
				}
				basic, e := f.store.LatestObservations(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(basic)
				if bytes.Contains(raw, []byte("Invented adapter")) || bytes.Contains(raw, []byte("dnsServers")) {
					t.Fatal("private adapter scope exported")
				}
				stale, e := v.RecheckAt(v.ServerNow.Add(3 * time.Minute))
				if e != nil || stale.Status != "stale" || stale.AdapterContext == nil {
					t.Fatal("stale mislabeled", e)
				}
				expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
				if e != nil || expired.AdapterContext != nil {
					t.Fatal("privacy expiry failed", e)
				}
				revoked := v
				revoked.Status = "revoked"
				revoked, e = revoked.RecheckAt(v.ServerNow)
				if e != nil || revoked.AdapterContext != nil {
					t.Fatal("authority retained")
				}
			})
		}
	}
}
func TestWindowsAdapterContextRetryRestartAndConsentRecheck(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := adapterConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runAdaptersOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(raw))
			req.Body = io.NopCloser(bytes.NewReader(raw))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("fixture lost response")
			}
			return response, nil
		}, func() (windowsadapters.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, g, grant string, at time.Time) (windowsadapters.Snapshot, error) {
			calls++
			return adapterSourceFixture(ctx, g, grant, at)
		})
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	before := f.view(t, time.Now().UTC())
	state.Close()
	f.store.Close()
	f.open(t)
	state, e = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	report, e := run()
	if e != nil || !report.RetriedPending || calls != 1 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("exact retry changed", e)
	}
	after := f.view(t, time.Now().UTC())
	if !after.ReceivedAt.Equal(*before.ReceivedAt) || !after.AdapterContext.CollectedAt.Equal(before.AdapterContext.CollectedAt) {
		t.Fatal("retry refreshed age")
	}
	// Revocation immediately after capture blocks stage/transmission.
	c.Enabled = true
	sent := false
	_, e = runAdaptersOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowsadapters.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, g, grant string, at time.Time) (windowsadapters.Snapshot, error) {
		c.Enabled = false
		return adapterSourceFixture(ctx, g, grant, at)
	})
	if !errors.Is(e, ErrState) || sent {
		t.Fatal("revoked grant transmitted", e)
	}
}
func TestWindowsAdapterContextWireRejectsPromotedOrMalformedFrames(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	base, _, e := collectFrameWithDependencies(context.Background(), f.material.config, 1, nil, nil, nil, startupWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	ac := adapterConsentFixture(f.material)
	good, raw, e := appendWindowsAdapterContext(context.Background(), f.material, base, ac, adapterSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*frame){func(v *frame) { v.SchemaVersion = FrameWindowsUpdatesVersion }, func(v *frame) { v.WindowsAdapterContext = nil }, func(v *frame) {
		v.WindowsAdapterContext.CollectedAt = v.WindowsAdapterContext.CollectedAt.Add(time.Nanosecond)
	}, func(v *frame) { v.WindowsAdapterContext.Rows[0].DNSServers.Addresses = []string{"example.org"} }, func(v *frame) { v.WindowsAdapterContext.Rows[0].TxQuality = "unknown" }} {
		var changed frame
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		b, _ := json.Marshal(changed)
		if _, e = decodeFrameForConfig(b, 1, f.material.config); e == nil {
			t.Fatal("sender admitted malformed frame")
		}
		if _, e = lanstore.ValidateFrame(b, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted malformed frame")
		}
	}
	if !lanstore.FrameMatchesCollectionProfile(lanstore.Frame{SchemaVersion: good.SchemaVersion, WindowsAdapterContext: good.WindowsAdapterContext, WindowsInventory: good.WindowsInventory, Observation: good.Observation}, windowsmanaged.CollectionProfile) {
		t.Fatal("profile rejected")
	}
}

func TestWindowsAdapterContextFrameBudgetPreservesBindings(t *testing.T) {
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
	f.Observation.Privacy = []string{strings.Repeat("a", 3000), strings.Repeat("b", 3000), strings.Repeat("c", 3000)}
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
	digest := f.WindowsServiceStartup.ServicesSHA256
	capture := f.WindowsInventory.CollectedAt
	f, _, err = appendWindowsUpdates(ctx, m, f, updatesConsentFixture(m), updatesSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	s, err := adapterSourceFixture(ctx, f.WindowsInventory.GenerationID, adapterConsentFixture(m).GrantID, capture)
	if err != nil {
		t.Fatal(err)
	}
	row := s.Rows[0]
	s.Rows = []windowsadapters.Adapter{}
	s.ObservedCount = 32
	for i := 1; i <= 32; i++ {
		v := row
		v.IfIndex = uint32(i)
		v.IPv6IfIndex = uint32(i)
		v.Name = strings.Repeat("a", 96)
		s.Rows = append(s.Rows, v)
	}
	s, err = windowsadapters.FitBudget(s, windowsadapters.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsAdapterContext(ctx, m, f, adapterConsentFixture(m), func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error) { return s, nil })
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.WindowsInventory)
	if len(raw) > MaxFrameBytes || !bytes.Equal(base, after) || f.WindowsServiceStartup.ServicesSHA256 != digest || !f.WindowsAdapterContext.CollectedAt.Equal(capture) || f.WindowsAdapterContext.ObservedCount != 32 || !f.WindowsAdapterContext.Truncated {
		t.Fatal("budget lost original capture/binding")
	}
	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	self := false
	for _, v := range f.WindowsProcessMetrics.Rows {
		if v.PID == 7 {
			self = true
		}
	}
	if !self {
		t.Fatal("protected self metric trimmed")
	}
}

func TestWindowsAdapterContextPendingReplacementAndPreSendChecks(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := adapterConsentFixture(m)
	calls := 0
	var sent frame
	send := func(req *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(req.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	read := func() (windowsadapters.Consent, bool) { return c, c.Enabled }
	run := func(read func() (windowsadapters.Consent, bool), collect adapterContextCollector) (Report, error) {
		return runAdaptersOnly(context.Background(), m, state, send, read, collect)
	}
	run(read, adapterSourceFixture)
	first := sent.Sequence
	c.GrantID = strings.Repeat("7", 32)
	report, _ := run(read, adapterSourceFixture)
	if !report.DiscardedUnconsented || sent.Sequence <= first || sent.WindowsAdapterContext.GrantID != c.GrantID {
		t.Fatal("replacement replayed pending")
	}
	c.Enabled = false
	report, _ = run(read, func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error) {
		t.Fatal("disabled collection")
		return windowsadapters.Snapshot{}, nil
	})
	if !report.DiscardedUnconsented || sent.WindowsAdapterContext != nil || sent.SchemaVersion != FrameWindowsInventoryVersion {
		t.Fatal("disabled pending transmitted")
	}
	p, _ := state.Pending()
	if p == nil || state.Discard(p.Digest) != nil {
		t.Fatal("pending fixture")
	}
	c.Enabled = true
	reads := 0
	_, e = run(func() (windowsadapters.Consent, bool) { reads++; return c, reads < 4 }, adapterSourceFixture)
	if !errors.Is(e, ErrState) || reads != 4 || calls != 3 {
		t.Fatal("pre-send consent not authoritative", e, reads, calls)
	}
	p, _ = state.Pending()
	if p == nil || state.Discard(p.Digest) != nil {
		t.Fatal("sequence state reset")
	}
	reads = 0
	_, e = run(func() (windowsadapters.Consent, bool) { reads++; return c, reads < 2 }, func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error) {
		t.Fatal("revoked source read")
		return windowsadapters.Snapshot{}, nil
	})
	if !errors.Is(e, ErrState) || reads != 2 {
		t.Fatal("pre-source consent not authoritative", e)
	}
}
