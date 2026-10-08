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
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func processConsentFixture(m Material) windowsprocessmetrics.Consent {
	return windowsprocessmetrics.Consent{SchemaVersion: windowsprocessmetrics.ConsentVersion, Scope: windowsprocessmetrics.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("e", 32), Enabled: true}
}
func processSourceFixture(ctx context.Context, pids []uint32, generation, grant string, inventoryAt time.Time) (windowsprocessmetrics.Snapshot, error) {
	sampler := windowsprocessmetrics.NewSamplerWithReader(func(context.Context, uint32) windowsprocessmetrics.Reading {
		return windowsprocessmetrics.Reading{Creation: 1, Memory: 123456789}
	}, time.Now, 4)
	return sampler.Sample(ctx, pids, generation, grant, inventoryAt)
}
func TestWindowsProcessMetricsActualSenderIngressStoreRetryAndIndependentDisable(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { state.Close() }()
	c := processConsentFixture(f.material)
	events := eventConsentFixture(f.material)
	calls := 0
	denied := false
	source := func(ctx context.Context, pids []uint32, g, grant string, at time.Time) (windowsprocessmetrics.Snapshot, error) {
		calls++
		s, e := processSourceFixture(ctx, pids, g, grant, at)
		if denied {
			s.Rows[0].CPUQuality = "denied"
			s.Rows[0].MemoryQuality = "denied"
			s.Rows[0].MemoryBytes = nil
			s.Rows[0].CPUPercent = nil
		}
		return s, e
	}
	var bodies [][]byte
	var receipts []lanstore.Receipt
	send := func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		bodies = append(bodies, bytes.Clone(b))
		response := f.serve(t, r, http.StatusOK)
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		var receipt lanstore.Receipt
		json.Unmarshal(raw, &receipt)
		receipts = append(receipts, receipt)
		if len(bodies) == 1 {
			return nil, errors.New("invented response loss")
		}
		response.Body = io.NopCloser(bytes.NewReader(raw))
		return response, nil
	}
	run := func() (Report, error) {
		return runUsingStateWithProcessMetricsDependencies(ctx, f.material, state, nil, nil, nil, windowsSource, send, func() (windowseventhealth.Consent, bool) { return events, events.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { v := volumeConsentFixture(f.material); return v, true }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return c, c.Enabled }, source)
	}
	if _, err = run(); !errors.Is(err, ErrTransport) {
		t.Fatal(err)
	}
	before := f.view(t, time.Now().UTC())
	if before.ProcessMetrics == nil || before.Events == nil {
		t.Fatal("combined capabilities absent")
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
		t.Fatal("exact retry altered", err)
	}
	after := f.view(t, time.Now().UTC())
	if after.ProcessMetrics == nil || !after.ProcessMetrics.CollectedAt.Equal(before.ProcessMetrics.CollectedAt) {
		t.Fatal("restart refreshed volume capture")
	}
	stale := f.view(t, time.Now().UTC().Add(3*time.Minute))
	if stale.Status != "stale" || stale.ProcessMetrics == nil {
		t.Fatal("staleness hidden")
	}
	if expired := f.view(t, time.Now().UTC().Add(25*time.Hour)); expired.ProcessMetrics != nil {
		t.Fatal("expired volume rows retained in view")
	}
	observations, err := f.store.LatestObservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(observations)
	if bytes.Contains(public, []byte("123456789")) {
		t.Fatal("volume identity leaked to basic evidence")
	}
	denied = true
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest := f.view(t, time.Now().UTC())
	if latest.ProcessMetrics == nil || latest.ProcessMetrics.Rows[0].CPUQuality != "denied" || latest.ProcessMetrics.Rows[0].MemoryBytes != nil {
		t.Fatal("denial reused prior capacity")
	}
	c.Enabled = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest = f.view(t, time.Now().UTC())
	if latest.ProcessMetrics != nil || latest.Events == nil || calls != 2 {
		t.Fatal("volume disable changed event consent")
	}
	var sent frame
	json.Unmarshal(bodies[len(bodies)-1], &sent)
	if sent.SchemaVersion != FrameWindowsCapabilitiesVersion {
		t.Fatal("event+volume v3 compatibility changed")
	}
	c.Enabled = true
	events.Enabled = false
	denied = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest = f.view(t, time.Now().UTC())
	if latest.ProcessMetrics == nil || latest.Events != nil {
		t.Fatal("volumes require unrelated event consent")
	}
	events.Enabled = false
	c.Enabled = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(bodies[len(bodies)-1], &sent)
	if sent.SchemaVersion != FrameWindowsCapabilitiesVersion {
		t.Fatal("volume v3 compatibility changed")
	}
}
func TestWindowsProcessMetricsPendingRevocationReplacementAndConsentRace(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	c := processConsentFixture(m)
	events := eventConsentFixture(m)
	calls := 0
	var sent frame
	send := func(r *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(r.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	run := func(source processMetricCollector) (Report, error) {
		return runUsingStateWithProcessMetricsDependencies(context.Background(), m, state, nil, nil, nil, windowsSource, send, func() (windowseventhealth.Consent, bool) { return events, true }, eventSourceFixture, nil, nil, func() (windowsprocessmetrics.Consent, bool) { return c, c.Enabled }, source)
	}
	run(processSourceFixture)
	pending, _ := state.Pending()
	if pending == nil || sent.WindowsProcessMetrics == nil || sent.WindowsEvents == nil {
		t.Fatal("no pending combined frame")
	}
	old := pending.Sequence
	c.GrantID = strings.Repeat("c", 32)
	report, _ := run(processSourceFixture)
	if !report.DiscardedUnconsented || calls != 2 || sent.Sequence <= old || sent.WindowsProcessMetrics.GrantID != c.GrantID {
		t.Fatal("replaced grant replayed old frame")
	}
	c.Enabled = false
	report, _ = run(processSourceFixture)
	if !report.DiscardedUnconsented || sent.WindowsProcessMetrics != nil || sent.WindowsEvents == nil || sent.SchemaVersion != FrameWindowsEventsVersion {
		t.Fatal("revoked volume pending was sent")
	}
	pending, _ = state.Pending()
	state.Discard(pending.Digest)
	c.Enabled = true
	_, err = run(func(ctx context.Context, pids []uint32, g, grant string, at time.Time) (windowsprocessmetrics.Snapshot, error) {
		s, e := processSourceFixture(ctx, pids, g, grant, at)
		c.Enabled = false
		return s, e
	})
	if err == nil || calls != 3 {
		t.Fatal("consent revoked during capture still sent")
	}
}
func TestWindowsProcessMetricsIngressStrictVersionAndScope(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, windowsSource)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsProcessMetrics(context.Background(), m, f, processConsentFixture(m), processSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := lanstore.ValidateFrame(raw, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileComplete} {
		if lanstore.FrameMatchesCollectionProfile(parsed, profile) {
			t.Fatal("profile confusion")
		}
	}
	for name, change := range map[string]func(*frame){
		"old-v1": func(f *frame) { f.SchemaVersion = FrameWindowsInventoryVersion }, "old-v2": func(f *frame) { f.SchemaVersion = FrameWindowsEventsVersion },
		"old-v3": func(f *frame) { f.SchemaVersion = FrameWindowsCapabilitiesVersion }, "scope": func(f *frame) { f.WindowsProcessMetrics.Scope = windowsmanagedProfileForTest }, "generation": func(f *frame) { f.WindowsProcessMetrics.GenerationID = "sample_" + strings.Repeat("a", 32) },
		"future": func(f *frame) { f.WindowsProcessMetrics.CollectedAt = f.Observation.GeneratedAt.Add(time.Second) }, "null": func(f *frame) { f.WindowsProcessMetrics = nil },
		"contradiction": func(f *frame) { f.WindowsProcessMetrics.Rows[0].MemoryQuality = "denied" },
	} {
		t.Run(name, func(t *testing.T) {
			var copy frame
			json.Unmarshal(raw, &copy)
			change(&copy)
			bad, _ := json.Marshal(copy)
			if _, e := lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
				t.Fatal("invalid ingress accepted")
			}
			if _, e := decodeFrameForConfig(bad, 1, m.config); e == nil {
				t.Fatal("invalid pending accepted")
			}
		})
	}
	for name, replace := range map[string]string{"null-event": `"windowsEvents":null,`, "unknown": `"extra":false,`, "duplicate": `"sequence":1,`} {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte("{"+replace), raw[1:]...)
			if _, e := lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
				t.Fatal("extra/null ingress accepted")
			}
			if _, e := decodeFrameForConfig(bad, 1, m.config); e == nil {
				t.Fatal("extra/null pending accepted")
			}
		})
	}
}
func TestWindowsProcessMetricsMaximalCombinedEnvelopePreservesCountsAndCapture(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	collect := func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		r := syntheticWindowsReport(time.Now().UTC())
		r.Processes.Rows = []windowsinventory.Process{}
		for i := 1; i <= 128; i++ {
			r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: uint32(i), Name: strings.Repeat("p", 250), Threads: 1})
		}
		r.Software.Quality = "healthy"
		r.Software.Complete = true
		for i := 1; i <= 128; i++ {
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("s", 240), Version: "1", Publisher: "Fixture", RegistryView: "64"})
		}
		return windowsmanaged.FromReport(r, g)
	}
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, collect)
	if err != nil {
		t.Fatal(err)
	}
	f.Observation.Privacy = []string{strings.Repeat("a", 4000), strings.Repeat("b", 4000), strings.Repeat("c", 4000)}
	f, _, err = appendWindowsEvents(context.Background(), m, f, eventConsentFixture(m), eventSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	original, err := volumeSourceFixture(context.Background(), f.WindowsInventory.GenerationID, volumeConsentFixture(m), m.binding)
	if err != nil {
		t.Fatal(err)
	}
	original.Rows = nil
	original.ObservedCount = 64
	original.Complete = false
	original.Truncated = true
	original.Quality = "bounded"
	for i := 0; i < 40; i++ {
		original.Rows = append(original.Rows, windowsvolumes.Volume{VolumeID: fmt.Sprintf(`\\?\Volume{11111111-2222-3333-4444-%012x}\`, i), DriveType: "fixed", Quality: "observed", Capacity: &windowsvolumes.Capacity{TotalBytes: "18446744073709551615", FreeBytes: "18446744073709551615", AvailableBytes: "18446744073709551615"}})
	}
	original, err = windowsvolumes.FitBudget(original, windowsvolumes.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsVolumes(context.Background(), m, f, volumeConsentFixture(m), func(context.Context, string, windowsvolumes.Consent, string) (windowsvolumes.Snapshot, error) {
		return original, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxFrameBytes || !f.WindowsVolumes.CollectedAt.Equal(original.CollectedAt) || f.WindowsVolumes.ObservedCount != 64 || !f.WindowsVolumes.CountExact || !f.WindowsVolumes.Truncated || len(f.WindowsVolumes.Rows) >= len(original.Rows) {
		t.Fatal("envelope trim lost truth or failed to exercise remaining budget", len(raw), len(f.WindowsVolumes.Rows), len(original.Rows))
	}
	volumeCapture := f.WindowsVolumes.CollectedAt
	volumeCount := f.WindowsVolumes.ObservedCount
	metrics, err := processSourceFixture(context.Background(), func() []uint32 {
		ids := []uint32{}
		for _, p := range f.WindowsInventory.Processes.Rows {
			ids = append(ids, p.PID)
		}
		return ids
	}(), f.WindowsInventory.GenerationID, processConsentFixture(m).GrantID, f.WindowsInventory.CollectedAt)
	if err != nil {
		t.Fatal(err)
	}
	metricCapture := metrics.CollectedAt
	f, raw, err = appendWindowsProcessMetrics(context.Background(), m, f, processConsentFixture(m), func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
		return metrics, nil
	})
	if err != nil {
		t.Fatal("full v3 frame blocked v4", err)
	}
	if len(raw) > MaxFrameBytes || !f.WindowsVolumes.CollectedAt.Equal(volumeCapture) || f.WindowsVolumes.ObservedCount != volumeCount || !f.WindowsProcessMetrics.CollectedAt.Equal(metricCapture) || int(f.WindowsProcessMetrics.ObservedCount) != len(f.WindowsInventory.Processes.Rows) {
		t.Fatal("combined trim lost capture/count")
	}
	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProcessMetricsEveryOptionalCombinationAndSamplerPipeline(t *testing.T) {
	for bits := 0; bits < 8; bits++ {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			pc, ec, vc := processConsentFixture(f.material), eventConsentFixture(f.material), volumeConsentFixture(f.material)
			pc.Enabled = bits&1 != 0
			ec.Enabled = bits&2 != 0
			vc.Enabled = bits&4 != 0
			calls := 0
			sampler := windowsprocessmetrics.NewSamplerWithReader(func(context.Context, uint32) windowsprocessmetrics.Reading {
				calls++
				return windowsprocessmetrics.Reading{Creation: 1, Kernel: 100, Memory: 987654321}
			}, time.Now, 4)
			var sent frame
			run := func() (Report, error) {
				return runUsingStateWithProcessMetricsDependencies(context.Background(), f.material, state, nil, nil, nil, windowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					sent = frame{}
					json.Unmarshal(raw, &sent)
					return f.serve(t, req, http.StatusOK), nil
				}, func() (windowseventhealth.Consent, bool) { return ec, ec.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, vc.Enabled }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, pc.Enabled }, sampler.Sample)
			}
			if _, e = run(); e != nil {
				t.Fatal(e)
			}
			view := f.view(t, time.Now().UTC())
			if (view.ProcessMetrics != nil) != pc.Enabled || (view.Events != nil) != ec.Enabled || (view.Volumes != nil) != vc.Enabled {
				t.Fatal("unselected scope changed")
			}
			want := FrameWindowsInventoryVersion
			if ec.Enabled {
				want = FrameWindowsEventsVersion
			}
			if vc.Enabled {
				want = FrameWindowsCapabilitiesVersion
			}
			if pc.Enabled {
				want = FrameWindowsProcessMetricsVersion
			}
			if sent.SchemaVersion != want {
				t.Fatal("wire version", sent.SchemaVersion, want)
			}
			if !pc.Enabled {
				if calls != 0 {
					t.Fatal("unconsented native reader reached")
				}
				return
			}
			if view.ProcessMetrics.Rows[0].CPUQuality != "first-sample" || view.ProcessMetrics.Rows[0].CPUPercent != nil || *view.ProcessMetrics.Rows[0].MemoryBytes != "987654321" {
				t.Fatal("first sample lied")
			}
			if _, e = run(); e != nil {
				t.Fatal(e)
			}
			view = f.view(t, time.Now().UTC())
			p := view.ProcessMetrics.Rows[0]
			if p.CPUQuality != "observed" || p.CPUPercent == nil || *p.CPUPercent != 0 || calls != 2 {
				t.Fatal("actual sampler counter delta did not reach view")
			}
		})
	}
}
