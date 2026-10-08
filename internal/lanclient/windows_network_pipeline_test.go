//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func networkConsentFixture(m Material) windowsnetwork.Consent {
	return windowsnetwork.Consent{SchemaVersion: windowsnetwork.ConsentVersion, Scope: windowsnetwork.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("e", 32), Enabled: true}
}
func networkSourceFixture(ctx context.Context, generation, grant string, capturedAt time.Time) (windowsnetwork.Snapshot, error) {
	return windowsnetwork.CollectWithReader(ctx, generation, grant, capturedAt, func(protocol, family string, buf []byte) (uint32, error) {
		size := uint32(4)
		if protocol == "tcp" && family == "ipv4" {
			size = 28
		}
		if uint32(len(buf)) < size {
			return size, windowsnetwork.ErrInsufficientBuffer
		}
		if size == 28 {
			binary.LittleEndian.PutUint32(buf, 1)
			binary.LittleEndian.PutUint32(buf[4:], 5) // established
			copy(buf[8:12], []byte{192, 0, 2, 8})
			binary.BigEndian.PutUint16(buf[12:14], 43210)
			copy(buf[16:20], []byte{203, 0, 113, 9})
			binary.BigEndian.PutUint16(buf[20:22], 443)
			binary.LittleEndian.PutUint32(buf[24:], 777)
		}
		return size, nil
	})
}

func TestWindowsNetworkActualSenderIngressStoreRetryAndIndependentDisable(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { state.Close() }()
	c := networkConsentFixture(f.material)
	events := eventConsentFixture(f.material)
	calls := 0
	denied := false
	source := func(ctx context.Context, g, grant string, at time.Time) (windowsnetwork.Snapshot, error) {
		calls++
		s, e := networkSourceFixture(ctx, g, grant, at)
		if denied {
			s.Quality = "denied"
			s.CountExact = false
			s.ObservedCount = 0
			s.Rows = []windowsnetwork.Endpoint{}
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
		return runUsingStateWithNetworkDependencies(ctx, f.material, state, nil, nil, nil, windowsSource, send, func() (windowseventhealth.Consent, bool) { return events, events.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { v := volumeConsentFixture(f.material); return v, true }, volumeSourceFixture, nil, nil, func() (windowsnetwork.Consent, bool) { return c, c.Enabled }, source)
	}
	if _, err = run(); !errors.Is(err, ErrTransport) {
		t.Fatal(err)
	}
	before := f.view(t, time.Now().UTC())
	if before.Network == nil || before.Events == nil {
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
	if after.Network == nil || !after.Network.CollectedAt.Equal(before.Network.CollectedAt) {
		t.Fatal("restart refreshed volume capture")
	}
	stale := f.view(t, time.Now().UTC().Add(3*time.Minute))
	if stale.Status != "stale" || stale.Network == nil {
		t.Fatal("staleness hidden")
	}
	if expired := f.view(t, time.Now().UTC().Add(25*time.Hour)); expired.Network != nil {
		t.Fatal("expired volume rows retained in view")
	}
	observations, err := f.store.LatestObservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(observations)
	if bytes.Contains(public, []byte("203.0.113.9")) {
		t.Fatal("volume identity leaked to basic evidence")
	}
	denied = true
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest := f.view(t, time.Now().UTC())
	if latest.Network == nil || latest.Network.Quality != "denied" || len(latest.Network.Rows) != 0 {
		t.Fatal("denial reused prior capacity")
	}
	c.Enabled = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest = f.view(t, time.Now().UTC())
	if latest.Network != nil || latest.Events == nil || calls != 2 {
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
	if latest.Network == nil || latest.Events != nil {
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
func TestWindowsNetworkPendingRevocationReplacementAndConsentRace(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	c := networkConsentFixture(m)
	events := eventConsentFixture(m)
	calls := 0
	var sent frame
	send := func(r *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(r.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	run := func(source networkCollector) (Report, error) {
		return runUsingStateWithNetworkDependencies(context.Background(), m, state, nil, nil, nil, windowsSource, send, func() (windowseventhealth.Consent, bool) { return events, true }, eventSourceFixture, nil, nil, nil, nil, func() (windowsnetwork.Consent, bool) { return c, c.Enabled }, source)
	}
	run(networkSourceFixture)
	pending, _ := state.Pending()
	if pending == nil || sent.WindowsNetwork == nil || sent.WindowsEvents == nil {
		t.Fatal("no pending combined frame")
	}
	old := pending.Sequence
	c.GrantID = strings.Repeat("c", 32)
	report, _ := run(networkSourceFixture)
	if !report.DiscardedUnconsented || calls != 2 || sent.Sequence <= old || sent.WindowsNetwork.GrantID != c.GrantID {
		t.Fatal("replaced grant replayed old frame")
	}
	c.Enabled = false
	report, _ = run(networkSourceFixture)
	if !report.DiscardedUnconsented || sent.WindowsNetwork != nil || sent.WindowsEvents == nil || sent.SchemaVersion != FrameWindowsEventsVersion {
		t.Fatal("revoked volume pending was sent")
	}
	pending, _ = state.Pending()
	state.Discard(pending.Digest)
	c.Enabled = true
	_, err = run(func(ctx context.Context, g, grant string, at time.Time) (windowsnetwork.Snapshot, error) {
		s, e := networkSourceFixture(ctx, g, grant, at)
		c.Enabled = false
		return s, e
	})
	if err == nil || calls != 3 {
		t.Fatal("consent revoked during capture still sent")
	}
}
func TestWindowsNetworkIngressStrictVersionAndScope(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, windowsSource)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsNetwork(context.Background(), m, f, networkConsentFixture(m), networkSourceFixture)
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
		"old-v3": func(f *frame) { f.SchemaVersion = FrameWindowsCapabilitiesVersion }, "scope": func(f *frame) { f.WindowsNetwork.Scope = windowsmanagedProfileForTest }, "generation": func(f *frame) { f.WindowsNetwork.GenerationID = "sample_" + strings.Repeat("a", 32) },
		"future": func(f *frame) { f.WindowsNetwork.CollectedAt = f.Observation.GeneratedAt.Add(time.Second) }, "null": func(f *frame) { f.WindowsNetwork = nil },
		"contradiction": func(f *frame) { f.WindowsNetwork.Quality = "denied" },
		"old-v4":        func(f *frame) { f.SchemaVersion = FrameWindowsProcessMetricsVersion },
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
func TestWindowsNetworkEveryOptionalCombination(t *testing.T) {
	for bits := 0; bits < 16; bits++ {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			pc, ec, vc, nc := processConsentFixture(f.material), eventConsentFixture(f.material), volumeConsentFixture(f.material), networkConsentFixture(f.material)
			pc.Enabled = bits&1 != 0
			ec.Enabled = bits&2 != 0
			vc.Enabled = bits&4 != 0
			nc.Enabled = bits&8 != 0
			calls := 0
			var sent frame
			_, e = runUsingStateWithNetworkDependencies(context.Background(), f.material, state, nil, nil, nil, windowsSource, func(req *http.Request) (*http.Response, error) {
				raw, _ := io.ReadAll(req.Body)
				req.Body = io.NopCloser(bytes.NewReader(raw))
				json.Unmarshal(raw, &sent)
				return f.serve(t, req, http.StatusOK), nil
			}, func() (windowseventhealth.Consent, bool) { return ec, ec.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, vc.Enabled }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, pc.Enabled }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, nc.Enabled }, func(ctx context.Context, g, grant string, at time.Time) (windowsnetwork.Snapshot, error) {
				calls++
				return networkSourceFixture(ctx, g, grant, at)
			})
			if e != nil {
				t.Fatal(e)
			}
			view := f.view(t, time.Now().UTC())
			if (view.Network != nil) != nc.Enabled || (view.ProcessMetrics != nil) != pc.Enabled || (view.Events != nil) != ec.Enabled || (view.Volumes != nil) != vc.Enabled {
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
			if nc.Enabled {
				want = FrameWindowsNetworkVersion
			}
			if sent.SchemaVersion != want || calls != int(bits>>3) {
				t.Fatal("wire/consent mismatch", sent.SchemaVersion, want, calls)
			}
			if nc.Enabled && (view.Network.Rows[0].PID != 777 || view.Network.Rows[0].LocalAddress != "192.0.2.8") {
				t.Fatal("API PID metadata changed or required a process join")
			}
		})
	}
}

func TestWindowsNetworkMaximalCombinedEnvelopePreservesCountsAndCapture(t *testing.T) {
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
	network, err := networkSourceFixture(context.Background(), f.WindowsInventory.GenerationID, networkConsentFixture(m).GrantID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	capture := network.CollectedAt
	f, raw, err = appendWindowsNetwork(context.Background(), m, f, networkConsentFixture(m), func(context.Context, string, string, time.Time) (windowsnetwork.Snapshot, error) { return network, nil })
	if err != nil {
		t.Fatal("full v4 blocked v5", err)
	}
	if len(raw) > MaxFrameBytes || !f.WindowsNetwork.CollectedAt.Equal(capture) || f.WindowsNetwork.ObservedCount != 1 || !f.WindowsVolumes.CollectedAt.Equal(volumeCapture) || f.WindowsVolumes.ObservedCount != volumeCount || !f.WindowsProcessMetrics.CollectedAt.Equal(metricCapture) {
		t.Fatal("network trim lost captures/count")
	}

	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsNetworkCaptureFloorAndPreSendRevocation(t *testing.T) {
	t.Run("capture-floor", func(t *testing.T) {
		f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
		baseAt := time.Now().UTC().Add(-time.Second)
		first, _, e := collectWindowsFrame(context.Background(), f.material.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
			return windowsmanaged.FromReport(syntheticWindowsReport(baseAt), g)
		})
		if e != nil {
			t.Fatal(e)
		}
		first, raw, e := appendWindowsNetwork(context.Background(), f.material, first, networkConsentFixture(f.material), networkSourceFixture)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); e != nil {
			t.Fatal(e)
		}
		first.Sequence = 2
		first.WindowsInventory.GenerationID = "sample_" + strings.Repeat("b", 32)
		first.WindowsNetwork.GenerationID = first.WindowsInventory.GenerationID
		first.WindowsInventory.CollectedAt = first.WindowsInventory.CollectedAt.Add(time.Nanosecond)
		first.Observation.Observation.LastSeen = first.Observation.Observation.LastSeen.Add(time.Nanosecond)
		first.Observation.GeneratedAt = first.Observation.GeneratedAt.Add(time.Nanosecond)
		raw, _ = json.Marshal(first)
		if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
			t.Fatal("invalid replay fixture", e)
		}
		if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); !errors.Is(e, lanstore.ErrReplay) {
			t.Fatal("network capture floor bypass", e)
		}
		if got := f.view(t, time.Now().UTC()); got.Sequence == nil || *got.Sequence != 1 {
			t.Fatal("rejected network capture modified durable view")
		}
	})
	t.Run("before-send", func(t *testing.T) {
		m := windowsMaterialFixture(t, "http-test")
		state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
		if e != nil {
			t.Fatal(e)
		}
		defer state.Close()
		c := networkConsentFixture(m)
		reads, sends := 0, 0
		_, e = runUsingStateWithNetworkDependencies(context.Background(), m, state, nil, nil, nil, windowsSource, func(*http.Request) (*http.Response, error) { sends++; return nil, errors.New("must never send") }, nil, nil, nil, nil, nil, nil, func() (windowsnetwork.Consent, bool) { reads++; return c, reads < 3 }, networkSourceFixture)
		if !errors.Is(e, ErrState) || sends != 0 || reads != 3 {
			t.Fatal("revocation immediately before send was ignored", e, reads, sends)
		}
		pending, e := state.Pending()
		if e != nil || pending == nil {
			t.Fatal("unsent staged bytes were erased/reset", e)
		}
	})
}

func TestWindowsNetworkCaptureFloorSurvivesAbsentScope(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	baseAt := time.Now().UTC().Add(-time.Second)
	first, _, e := collectWindowsFrame(context.Background(), f.material.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		return windowsmanaged.FromReport(syntheticWindowsReport(baseAt), g)
	})
	if e != nil {
		t.Fatal(e)
	}
	first, raw, e := appendWindowsNetwork(context.Background(), f.material, first, networkConsentFixture(f.material), networkSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	networkAt := first.WindowsNetwork.CollectedAt
	first.SchemaVersion = FrameWindowsInventoryVersion
	first.WindowsNetwork = nil
	first.Sequence = 2
	first.WindowsInventory.GenerationID = "sample_" + strings.Repeat("b", 32)
	first.WindowsInventory.CollectedAt = networkAt.Add(-time.Nanosecond)
	first.Observation.Observation.LastSeen = first.WindowsInventory.CollectedAt
	first.Observation.GeneratedAt = time.Now().UTC()
	raw, _ = json.Marshal(first)
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal("invalid absent-scope fixture", e)
	}
	if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); !errors.Is(e, lanstore.ErrReplay) {
		t.Fatal("scope omission erased capture floor", e)
	}
	first.WindowsInventory.CollectedAt = networkAt.Add(time.Nanosecond)
	first.Observation.Observation.LastSeen = first.WindowsInventory.CollectedAt
	first.Observation.GeneratedAt = time.Now().UTC()
	raw, _ = json.Marshal(first)
	if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); e != nil {
		t.Fatal("legitimate scope disable blocked", e)
	}
	if got := f.view(t, time.Now().UTC()); got.Network != nil || got.Sequence == nil || *got.Sequence != 2 {
		t.Fatal("scope disable failed")
	}
}
