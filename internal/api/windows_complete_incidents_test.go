package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

type completeInboxFixture struct {
	*completeHealthFixture
	onIncidentGuard func(int)
	incidentGuards  int
	currentLeaf     string
}

func (f *completeInboxFixture) WindowsCapacityInputs(ctx context.Context, at time.Time) ([]windowscapacity.Input, error) {
	rows, e := f.completeHealthFixture.WindowsCapacityInputs(ctx, at)
	for i := range rows {
		rows[i].CurrentLeaf = f.currentLeaf
	}
	return rows, e
}
func (f *completeInboxFixture) WithWindowsCompleteServiceAuthority(ctx context.Context, in windowsservicehealth.Input, fn func(func(time.Time) error) error) error {
	return f.completeHealthFixture.WithWindowsCompleteServiceAuthority(ctx, in, func(authority func(time.Time) error) error {
		return fn(func(at time.Time) error {
			if e := authority(at); e != nil {
				return e
			}
			if in.CurrentLeaf != f.currentLeaf {
				return store.ErrWindowsIncident
			}
			return nil
		})
	})
}
func (f *completeInboxFixture) WithWindowsCompleteIncidentAuthority(ctx context.Context, in windowsservicehealth.Input, fn func(func(time.Time) error) error) error {
	return f.WithWindowsIncidentAuthority(ctx, in.Input, func(authority func(time.Time) error) error {
		guard := func(at time.Time) error {
			f.incidentGuards++
			if f.onIncidentGuard != nil {
				f.onIncidentGuard(f.incidentGuards)
			}
			if e := authority(at); e != nil {
				return e
			}
			if in.CurrentLeaf != f.currentLeaf {
				return store.ErrWindowsIncident
			}
			var source *windowsservicehealth.Provenance
			if f.sampleComplete != nil && f.sampleComplete.Source.Fresh(f.now) {
				p := f.sampleComplete.Source
				source = &p
			}
			if (source == nil) != (in.Selection == nil) || source != nil && *source != *in.Selection {
				return store.ErrWindowsIncident
			}
			return nil
		}
		if e := guard(f.now); e != nil {
			return e
		}
		return fn(guard)
	})
}
func completeInboxHandlerFixture(t *testing.T) (*operatorHandler, *completeInboxFixture, operatorRequest) {
	t.Helper()
	h, base, op, _ := completeHealthHandlerFixture(t)
	f := &completeInboxFixture{completeHealthFixture: base}
	f.currentLeaf = strings.Repeat("c", 64)
	h.app.windowsCapacity.source = f
	// Native-length name beyond legacy parser and preview, still within Win32 bounds.
	name := strings.Repeat("界", 100)
	f.sampleComplete.Rows[0].Name = name
	body := completeServiceBody(base)
	body["services"] = []string{name}
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete/policy"
	if w := completeServiceRequest(h, op, "POST", path, body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	start := f.now
	for i := 0; i <= 4; i++ {
		f.now = start.Add(time.Duration(i) * 30 * time.Second)
		if i == 4 {
			p := &f.sampleComplete.Source
			p.Sequence++
			p.CapturedAt = f.now
			p.CaptureFinishedAt = f.now
			p.ReceivedAt = f.now
			p.ExpiresAt = f.now.Add(24 * time.Hour)
			p.GenerationID, _ = windowsfullservices.GenerationID(f.inputs[0].DeviceID, p.GrantID, p.Sequence)
		}
		if e := h.app.windowsCapacity.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	return h, f, op
}
func completeInboxRequest(h *operatorHandler, op operatorRequest, method, path string, body any, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://maintenance.invalid"+path, strings.NewReader(string(raw)))
	r.Header.Set("Origin", op.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", op.session.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, op))
	for _, change := range changes {
		change(r)
	}
	w := httptest.NewRecorder()
	h.windowsCompleteIncidentsAPI(w, r)
	return w
}
func completeInboxRead(t *testing.T, h *operatorHandler, op operatorRequest, path string) windowsCompleteInboxView {
	t.Helper()
	w := completeInboxRequest(h, op, "GET", path, nil)
	var v windowsCompleteInboxView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return v
}

const completeInboxPath = "/api/fleet/windows-incidents/complete"

func TestCompleteIncidentRecorderProjectionAndAcknowledgement(t *testing.T) {
	h, f, op := completeInboxHandlerFixture(t)
	before, e := h.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	rawBefore, _ := windowsservicehealth.Encode(before)
	v := completeInboxRead(t, h, op, completeInboxPath)
	if v.SchemaVersion != "tracebolt.windows-incident-inbox.v2" || v.Total != 1 || len(v.Items) != 1 {
		t.Fatal(v)
	}
	row := v.Items[0]
	if row.Domain != "service-complete" || row.SourceKind != "windows_full_services" || row.OpeningSource == nil || row.LastBadSource == nil || row.CurrentSource == nil || row.Status != "attention" || len(row.ServiceName) <= 256 || row.StatusValidUntil == nil || !row.StatusValidUntil.Equal(f.now.Add(120*time.Second)) {
		t.Fatal(row)
	}
	legacySnapshot, e := h.app.store.WindowsIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(legacySnapshot.Targets()) != 0 {
		t.Fatal("full source inherited v1 target")
	}
	if w := completeInboxRequest(h, op, "POST", completeInboxPath+"/acknowledge", map[string]any{"key": row.Key}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	seen := completeInboxRead(t, h, op, completeInboxPath)
	if seen.Items[0].AcknowledgedAt == nil || seen.Items[0].ResolvedAt != nil || seen.Counts.Active != 1 || seen.Counts.Acknowledged != 1 {
		t.Fatal(seen)
	}
	first := *seen.Items[0].AcknowledgedAt
	f.now = f.now.Add(time.Second)
	if w := completeInboxRequest(h, op, "POST", completeInboxPath+"/acknowledge", map[string]any{"key": row.Key}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	again := completeInboxRead(t, h, op, completeInboxPath)
	if !again.Items[0].AcknowledgedAt.Equal(first) {
		t.Fatal("reack refreshed seen")
	}
	// Grant/source loss does not hide or close original episode history.
	f.sampleComplete = nil
	unknown := completeInboxRead(t, h, op, completeInboxPath)
	if unknown.Items[0].Status != "unknown" || unknown.Items[0].CurrentSource != nil || unknown.Items[0].StatusValidUntil != nil || unknown.Items[0].OpeningSource == nil || unknown.Items[0].Key != row.Key {
		t.Fatal(unknown)
	}
	if w := completeInboxRequest(h, op, "POST", completeInboxPath+"/acknowledge", map[string]any{"key": row.Key}); w.Code != 200 {
		t.Fatal("retained unavailable history cannot be marked seen", w.Code, w.Body.String())
	}
	after, _ := h.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
	rawAfter, _ := windowsservicehealth.Encode(after)
	if !bytes.Equal(rawBefore, rawAfter) {
		t.Fatal("inbox mutated source ledger")
	}
	// UI fixture bytes come from the actual Go DTO, never independently mocked.
	if os.Getenv("TRACEBOLT_WRITE_COMPLETE_INCIDENT_FIXTURE") == "1" {
		raw, e := json.MarshalIndent(map[string]any{"active": v, "acknowledged": seen, "unknown": unknown}, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile("../../web/src/windows-complete-incident-go-fixture.json", append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	f.inputs[0].Authorized = false
	hidden := completeInboxRead(t, h, op, completeInboxPath)
	if hidden.Total != 0 || hidden.Coverage.UnavailableDevices != 1 {
		t.Fatal("revoked original identity disclosed", hidden)
	}
}
func TestCompleteIncidentRecorderCommitAndClosedRequests(t *testing.T) {
	for _, mode := range []string{"generation", "grant", "current-leaf", "revoked", "session", "clock", "source-expiry", "source-return"} {
		t.Run(mode, func(t *testing.T) {
			h, f, op := completeInboxHandlerFixture(t)
			row := completeInboxRead(t, h, op, completeInboxPath).Items[0]
			live := true
			op.active = func() bool { return live }
			saved := f.sampleComplete
			if mode == "source-return" {
				f.sampleComplete = nil
			}
			if mode == "source-expiry" {
				f.now = f.sampleComplete.Source.CapturedAt.Add(299 * time.Second)
			}
			f.onIncidentGuard = func(n int) {
				if n != 3 {
					return
				}
				switch mode {
				case "generation":
					f.sampleComplete.Source.ManifestSHA256 = strings.Repeat("e", 64)
				case "grant":
					f.sampleComplete.Source.GrantRevision++
				case "current-leaf":
					f.currentLeaf = strings.Repeat("d", 64)
				case "revoked":
					f.inputs[0].Authorized = false
				case "session":
					live = false
				case "clock":
					f.now = f.now.Add(-time.Second)
				case "source-expiry":
					f.now = f.now.Add(2 * time.Second)
				case "source-return":
					f.sampleComplete = saved
				}
			}
			w := completeInboxRequest(h, op, "POST", completeInboxPath+"/acknowledge", map[string]any{"key": row.Key})
			if w.Code == 200 {
				t.Fatal("final guard admitted", mode)
			}
			snap, e := h.app.store.WindowsCompleteIncidentSnapshot(context.Background())
			if e != nil || len(snap.CompleteAcknowledgements) != 0 {
				t.Fatal("failed acknowledgement persisted", e)
			}
		})
	}
	h, f, op := completeInboxHandlerFixture(t)
	row := completeInboxRead(t, h, op, completeInboxPath).Items[0]
	for _, path := range []string{completeInboxPath + "?limit=51", completeInboxPath + "?limit=01", completeInboxPath + "?scope=all&scope=active", completeInboxPath + "?unknown=yes"} {
		if w := completeInboxRequest(h, op, "GET", path, nil); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	namedOp := operatorRequest{session: session, origin: op.origin, active: func() bool { _, e := auth.Lookup(session.Token); return e == nil }}
	completeInboxRead(t, h, namedOp, completeInboxPath)
	for _, mode := range []string{"extra", "csrf", "origin", "named", "old-key"} {
		body := map[string]any{"key": row.Key}
		named := op
		if mode == "extra" {
			body["sourceKind"] = "windows_full_services"
		}
		if mode == "named" {
			named = namedOp
		}
		if mode == "old-key" {
			body["key"] = strings.Repeat("a", 64)
		}
		w := completeInboxRequest(h, named, "POST", completeInboxPath+"/acknowledge", body, func(r *http.Request) {
			if mode == "csrf" {
				r.Header.Del("X-CSRF-Token")
			}
			if mode == "origin" {
				r.Header.Set("Origin", "https://other.invalid")
			}
		})
		if w.Code == 200 {
			t.Fatal("closed request admitted", mode)
		}
	}
	// A source capture older than 120 seconds can remain current when independently
	// evaluated recently; status deadline is source+300s, never source+120s.
	f.now = f.now.Add(150 * time.Second)
	inputs, e := f.WindowsCapacityInputs(windowsservicehealth.WithCompleteSelections(context.Background(), map[string][]string{f.inputs[0].DeviceID: {row.ServiceName}}), f.now)
	if e != nil {
		t.Fatal(e)
	}
	source := inputs[0].Services.Complete.Source
	at := f.now
	until := completeInboxStatusUntil("attention", &at, &source, f.inputs[0].AuthorityUntil)
	if until == nil || !until.Equal(f.now.Add(120*time.Second)) {
		t.Fatal("legacy source age leaked into v2", until)
	}
	// The combined endpoint preserves original v1 keys and durable seen metadata.
	h2, f2, op2 := completeInboxHandlerFixture(t)
	ctx := context.Background()
	inputs2, e := f2.WindowsCapacityInputs(ctx, f2.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h2.app.store.ConfigureWindowsCapacity(ctx, inputs2[0], true, 90, 0, f2.now); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			f2.now = f2.now.Add(30 * time.Second)
			f2.inputs[0].ReceivedAt = f2.now
			f2.inputs[0].Sequence++
		}
		if e = h2.app.windowsCapacity.evaluate(ctx); e != nil {
			t.Fatal(e)
		}
	}
	combined := completeInboxRead(t, h2, op2, completeInboxPath)
	if combined.Total != 2 {
		t.Fatal("combined family lost", combined)
	}
	var legacy windowsCompleteInboxItem
	for _, item := range combined.Items {
		if item.Domain == "disk" {
			legacy = item
		}
	}
	if legacy.SourceKind != "assessment_v1" || legacy.OpeningSource != nil || legacy.CurrentSource != nil {
		t.Fatal("legacy source was relabeled", legacy)
	}
	beforeLegacy, e := h2.app.store.WindowsIncidentSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := beforeLegacy.Targets()[legacy.Key]; !ok {
		t.Fatal("v1 key changed")
	}
	oldLeaf := f2.currentLeaf
	f2.onGuard = func(n int) {
		if n == 3 {
			f2.currentLeaf = strings.Repeat("e", 64)
		}
	}
	if w := completeInboxRequest(h2, op2, "POST", completeInboxPath+"/acknowledge", map[string]any{"key": legacy.Key}); w.Code == 200 {
		t.Fatal("v2 legacy row admitted changed leaf")
	}
	failedLegacy, e := h2.app.store.WindowsIncidentSnapshot(ctx)
	if e != nil || len(failedLegacy.Acknowledgements) != 0 {
		t.Fatal("legacy source write survived final leaf change", e)
	}
	f2.currentLeaf = oldLeaf
	f2.onGuard = nil
	if w := completeInboxRequest(h2, op2, "POST", completeInboxPath+"/acknowledge", map[string]any{"key": legacy.Key}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	afterLegacy, e := h2.app.store.WindowsCompleteIncidentSnapshot(ctx)
	if e != nil || afterLegacy.Acknowledgements[legacy.Key].Version != 1 || len(afterLegacy.CompleteAcknowledgements) != 0 {
		t.Fatal("legacy seen metadata was promoted", e)
	}

}
