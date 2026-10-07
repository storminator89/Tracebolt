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
	"localrmm/internal/lanstore"
	"localrmm/internal/windowseventhealth"
	"net/http"
	"strings"
	"testing"
	"time"
)

func eventConsentFixture(m Material) windowseventhealth.Consent {
	return windowseventhealth.Consent{SchemaVersion: windowseventhealth.ConsentVersion, Scope: windowseventhealth.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("e", 32), Enabled: true}
}
func eventSourceFixture(_ context.Context, g string, c windowseventhealth.Consent, _ string) (windowseventhealth.Snapshot, error) {
	at := time.Now().UTC()
	return windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: c.GrantID, GenerationID: g, CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 42, Level: 2, Provider: "Invented Provider", Timestamp: at.Add(-time.Minute)}}}, {Channel: "System", Quality: "denied", Reason: "windows_events_access_denied", Rows: []windowseventhealth.Event{}}}}, nil
}
func TestWindowsEventsActualSenderIngressStoreRetryAndDisable(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := eventConsentFixture(f.material)
	read := func() (windowseventhealth.Consent, bool) { return c, c.Enabled }
	calls := 0
	denied := false
	source := func(ctx context.Context, g string, c windowseventhealth.Consent, b string) (windowseventhealth.Snapshot, error) {
		calls++
		s, e := eventSourceFixture(ctx, g, c, b)
		if denied {
			for i := range s.Channels {
				s.Channels[i].Quality = "denied"
				s.Channels[i].Reason = "windows_events_access_denied"
				s.Channels[i].Complete = false
				s.Channels[i].ObservedCount = 0
				s.Channels[i].Rows = []windowseventhealth.Event{}
			}
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
		return runUsingStateWithEventDependencies(ctx, f.material, state, nil, nil, nil, windowsSource, send, read, source)
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	before := f.view(t, time.Now().UTC())
	if before.Events == nil || before.Events.Channels[1].Quality != "denied" {
		t.Fatal("events not persisted")
	}
	state.Close()
	f.store.Close()
	f.open(t)
	state, e = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	r, e := run()
	if e != nil || !r.Duplicate || calls != 1 || !bytes.Equal(bodies[0], bodies[1]) || !receipts[0].ReceivedAt.Equal(receipts[1].ReceivedAt) {
		t.Fatal("retry changed exact event report", e)
	}
	after := f.view(t, time.Now().UTC())
	if after.Events == nil || !after.Events.CollectedAt.Equal(before.Events.CollectedAt) {
		t.Fatal("restart refreshed event age")
	}
	stale := f.view(t, time.Now().UTC().Add(3*time.Minute))
	if stale.Status != "stale" || stale.Events == nil {
		t.Fatal("stale view lost truth")
	}
	expired := f.view(t, time.Now().UTC().Add(25*time.Hour))
	if expired.Events != nil {
		t.Fatal("expired metadata remains visible")
	}
	observations, err := f.store.LatestObservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(observations)
	if bytes.Contains(public, []byte("Invented Provider")) {
		t.Fatal("event metadata entered shared basic evidence")
	}
	denied = true
	if _, e = run(); e != nil {
		t.Fatal(e)
	}
	latest := f.view(t, time.Now().UTC())
	if latest.Events == nil || len(latest.Events.Channels[0].Rows) != 0 || latest.Events.Channels[0].Quality != "denied" {
		t.Fatal("denial reused old headers")
	}
	c.Enabled = false
	if _, e = run(); e != nil {
		t.Fatal(e)
	}
	if calls != 2 || f.view(t, time.Now().UTC()).Events != nil {
		t.Fatal("disabled consent collected or retained latest events")
	}
}
func TestWindowsEventsPendingRevocationAndConsentRace(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := eventConsentFixture(m)
	read := func() (windowseventhealth.Consent, bool) { return c, c.Enabled }
	calls := 0
	var sent frame
	send := func(r *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(r.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	run := func(source eventCollector) (Report, error) {
		return runUsingStateWithEventDependencies(context.Background(), m, state, nil, nil, nil, windowsSource, send, read, source)
	}
	run(eventSourceFixture)
	p, _ := state.Pending()
	if p == nil || sent.WindowsEvents == nil {
		t.Fatal("no pending events")
	}
	old := p.Sequence
	c.Enabled = false
	run(eventSourceFixture)
	if calls != 2 || sent.WindowsEvents != nil || sent.Sequence <= old {
		t.Fatal("revoked pending sent or sequence reset")
	}
	p, _ = state.Pending()
	state.Discard(p.Digest)
	c.Enabled = true
	_, e = run(func(ctx context.Context, g string, grant windowseventhealth.Consent, b string) (windowseventhealth.Snapshot, error) {
		s, e := eventSourceFixture(ctx, g, grant, b)
		c.Enabled = false
		return s, e
	})
	if e == nil || calls != 2 {
		t.Fatal("consent revoked during collection still sent")
	}
}
func TestWindowsEventsIngressRejectsScopeContentAndProfileConfusion(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, e := collectWindowsFrame(context.Background(), m.config, 1, windowsSource)
	if e != nil {
		t.Fatal(e)
	}
	f, b, e := appendWindowsEvents(context.Background(), m, f, eventConsentFixture(m), eventSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := lanstore.ValidateFrame(b, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileComplete} {
		if lanstore.FrameMatchesCollectionProfile(parsed, p) {
			t.Fatal("wrong identity profile")
		}
	}
	for _, change := range []func(*frame){func(f *frame) { f.SchemaVersion = FrameWindowsInventoryVersion }, func(f *frame) { f.WindowsEvents.Scope = "windows-inventory-v1" }, func(f *frame) { f.WindowsEvents.GenerationID = "sample_" + strings.Repeat("a", 32) }, func(f *frame) { f.WindowsEvents.CollectedAt = f.Observation.GeneratedAt.Add(time.Second) }} {
		var copy frame
		json.Unmarshal(b, &copy)
		change(&copy)
		bad, _ := json.Marshal(copy)
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("bad event frame admitted")
		}
	}
	_ = f
}
