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
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

const fixtureVolumeID = `\\?\Volume{11111111-2222-3333-4444-555555555555}\`

func volumeConsentFixture(m Material) windowsvolumes.Consent {
	return windowsvolumes.Consent{SchemaVersion: windowsvolumes.ConsentVersion, Scope: windowsvolumes.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("d", 32), Enabled: true}
}
func volumeSourceFixture(_ context.Context, generation string, c windowsvolumes.Consent, _ string) (windowsvolumes.Snapshot, error) {
	return windowsvolumes.Snapshot{SchemaVersion: windowsvolumes.SchemaVersion, Scope: windowsvolumes.Scope, GrantID: c.GrantID, GenerationID: generation, CollectedAt: time.Now().UTC(), Quality: "observed", Complete: true, CountExact: true, ObservedCount: 1, Rows: []windowsvolumes.Volume{{VolumeID: fixtureVolumeID, DriveType: "fixed", Quality: "observed", Capacity: &windowsvolumes.Capacity{TotalBytes: "100", FreeBytes: "18446744073709551615", AvailableBytes: "75"}}}}, nil
}
func TestWindowsVolumesActualSenderIngressStoreRetryAndIndependentDisable(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { state.Close() }()
	c := volumeConsentFixture(f.material)
	events := eventConsentFixture(f.material)
	calls := 0
	denied := false
	source := func(ctx context.Context, g string, c windowsvolumes.Consent, b string) (windowsvolumes.Snapshot, error) {
		calls++
		s, e := volumeSourceFixture(ctx, g, c, b)
		if denied {
			s.Quality = "denied"
			s.Reason = "windows_volumes_access_denied"
			s.Complete = false
			s.CountExact = false
			s.ObservedCount = 0
			s.Rows = []windowsvolumes.Volume{}
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
		return runUsingStateWithCapabilityDependencies(ctx, f.material, state, nil, nil, nil, windowsSource, send, func() (windowseventhealth.Consent, bool) { return events, events.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return c, c.Enabled }, source)
	}
	if _, err = run(); !errors.Is(err, ErrTransport) {
		t.Fatal(err)
	}
	before := f.view(t, time.Now().UTC())
	if before.Volumes == nil || before.Events == nil {
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
	if after.Volumes == nil || !after.Volumes.CollectedAt.Equal(before.Volumes.CollectedAt) {
		t.Fatal("restart refreshed volume capture")
	}
	stale := f.view(t, time.Now().UTC().Add(3*time.Minute))
	if stale.Status != "stale" || stale.Volumes == nil {
		t.Fatal("staleness hidden")
	}
	if expired := f.view(t, time.Now().UTC().Add(25*time.Hour)); expired.Volumes != nil {
		t.Fatal("expired volume rows retained in view")
	}
	observations, err := f.store.LatestObservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(observations)
	if bytes.Contains(public, []byte("11111111-2222")) {
		t.Fatal("volume identity leaked to basic evidence")
	}
	denied = true
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest := f.view(t, time.Now().UTC())
	if latest.Volumes == nil || latest.Volumes.Quality != "denied" || len(latest.Volumes.Rows) != 0 {
		t.Fatal("denial reused prior capacity")
	}
	c.Enabled = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest = f.view(t, time.Now().UTC())
	if latest.Volumes != nil || latest.Events == nil || calls != 2 {
		t.Fatal("volume disable changed event consent")
	}
	var sent frame
	json.Unmarshal(bodies[len(bodies)-1], &sent)
	if sent.SchemaVersion != FrameWindowsEventsVersion {
		t.Fatal("events-only v2 compatibility changed")
	}
	c.Enabled = true
	events.Enabled = false
	denied = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	latest = f.view(t, time.Now().UTC())
	if latest.Volumes == nil || latest.Events != nil {
		t.Fatal("volumes require unrelated event consent")
	}
	events.Enabled = false
	c.Enabled = false
	if _, err = run(); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(bodies[len(bodies)-1], &sent)
	if sent.SchemaVersion != FrameWindowsInventoryVersion {
		t.Fatal("default v1 compatibility changed")
	}
}
func TestWindowsVolumesPendingRevocationReplacementAndConsentRace(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	c := volumeConsentFixture(m)
	events := eventConsentFixture(m)
	calls := 0
	var sent frame
	send := func(r *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(r.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	run := func(source volumeCollector) (Report, error) {
		return runUsingStateWithCapabilityDependencies(context.Background(), m, state, nil, nil, nil, windowsSource, send, func() (windowseventhealth.Consent, bool) { return events, true }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return c, c.Enabled }, source)
	}
	run(volumeSourceFixture)
	pending, _ := state.Pending()
	if pending == nil || sent.WindowsVolumes == nil || sent.WindowsEvents == nil {
		t.Fatal("no pending combined frame")
	}
	old := pending.Sequence
	c.GrantID = strings.Repeat("c", 32)
	report, _ := run(volumeSourceFixture)
	if !report.DiscardedUnconsented || calls != 2 || sent.Sequence <= old || sent.WindowsVolumes.GrantID != c.GrantID {
		t.Fatal("replaced grant replayed old frame")
	}
	c.Enabled = false
	report, _ = run(volumeSourceFixture)
	if !report.DiscardedUnconsented || sent.WindowsVolumes != nil || sent.WindowsEvents == nil || sent.SchemaVersion != FrameWindowsEventsVersion {
		t.Fatal("revoked volume pending was sent")
	}
	pending, _ = state.Pending()
	state.Discard(pending.Digest)
	c.Enabled = true
	_, err = run(func(ctx context.Context, g string, grant windowsvolumes.Consent, b string) (windowsvolumes.Snapshot, error) {
		s, e := volumeSourceFixture(ctx, g, grant, b)
		c.Enabled = false
		return s, e
	})
	if err == nil || calls != 3 {
		t.Fatal("consent revoked during capture still sent")
	}
}
func TestWindowsVolumesIngressStrictVersionAndScope(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, windowsSource)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsVolumes(context.Background(), m, f, volumeConsentFixture(m), volumeSourceFixture)
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
		"scope": func(f *frame) { f.WindowsVolumes.Scope = windowsmanagedProfileForTest }, "generation": func(f *frame) { f.WindowsVolumes.GenerationID = "sample_" + strings.Repeat("a", 32) },
		"future": func(f *frame) { f.WindowsVolumes.CollectedAt = f.Observation.GeneratedAt.Add(time.Second) }, "null": func(f *frame) { f.WindowsVolumes = nil },
		"contradiction": func(f *frame) { f.WindowsVolumes.Rows[0].Quality = "denied" },
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

const windowsmanagedProfileForTest = "windows-inventory-v1"

func TestWindowsVolumesEnvelopeBudgetPreservesCountsAndCapture(t *testing.T) {
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
	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}
