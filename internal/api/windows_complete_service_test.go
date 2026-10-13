package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type completeHealthFixture struct {
	*groupServiceFixture
	sampleComplete *windowsservicehealth.CompleteSample
}

func (f *completeHealthFixture) WindowsCapacityInputs(ctx context.Context, at time.Time) ([]windowscapacity.Input, error) {
	rows, e := f.groupServiceFixture.WindowsCapacityInputs(ctx, at)
	if e != nil {
		return nil, e
	}
	selected, e := windowsservicehealth.CompleteSelections(ctx)
	if e != nil {
		return nil, e
	}
	for i := range rows {
		if names, ok := selected[rows[i].DeviceID]; ok && f.sampleComplete != nil {
			sample := &windowsservicehealth.CompleteSample{Source: f.sampleComplete.Source, Rows: []windowsfullservices.Row{}}
			for _, row := range f.sampleComplete.Rows {
				for _, name := range names {
					if row.Name == name {
						sample.Rows = append(sample.Rows, row)
					}
				}
			}
			rows[i].Services.Complete = sample
		}
	}
	return rows, nil
}
func (f *completeHealthFixture) WithWindowsCompleteServiceAuthority(ctx context.Context, in windowsservicehealth.Input, fn func(func(time.Time) error) error) error {
	return f.WithWindowsIncidentAuthority(ctx, in.Input, func(authority func(time.Time) error) error {
		guard := func(at time.Time) error {
			if e := authority(at); e != nil {
				return e
			}
			if in.Selection != nil && (f.sampleComplete == nil || f.sampleComplete.Source != *in.Selection || !f.sampleComplete.Source.Fresh(f.now)) {
				return windowsservicehealth.ErrInvalid
			}
			return nil
		}
		if e := guard(f.now); e != nil {
			return e
		}
		return fn(guard)
	})
}
func completeHealthHandlerFixture(t *testing.T) (*operatorHandler, *completeHealthFixture, operatorRequest, string) {
	h, base, op, path := groupServiceHandlerFixture(t)
	p := windowsservicehealth.Provenance{Kind: windowsservicehealth.CompleteSourceKind, GrantID: strings.Repeat("a", 32), GrantRevision: 1, ManifestSHA256: strings.Repeat("b", 64), Sequence: 1, CapturedAt: base.now, CaptureFinishedAt: base.now, ReceivedAt: base.now, ExpiresAt: base.now.Add(24 * time.Hour), RowCount: 2051}
	p.GenerationID, _ = windowsfullservices.GenerationID(base.inputs[0].DeviceID, p.GrantID, p.Sequence)
	state, display := "stopped", "Complete inventory fixture service"
	f := &completeHealthFixture{groupServiceFixture: base, sampleComplete: &windowsservicehealth.CompleteSample{Source: p, Rows: []windowsfullservices.Row{{Name: "BeyondPreviewService", DisplayName: &display, DisplayNameQuality: "observed", State: &state, StateQuality: "observed", PIDQuality: "unavailable"}}}}
	h.app.windowsCapacity.source = f
	h.fleetGroupSources = []fleetGroupSource{f}
	return h, f, op, path + "-complete"
}
func completeServiceRequest(h *operatorHandler, op operatorRequest, method, path string, body any, change ...func(*http.Request)) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://maintenance.invalid"+path, strings.NewReader(string(raw)))
	r.Header.Set("Origin", op.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", op.session.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, op))
	for _, f := range change {
		f(r)
	}
	w := httptest.NewRecorder()
	h.windowsServiceAPI(w, r)
	return w
}
func completeServiceBody(f *completeHealthFixture) map[string]any {
	return map[string]any{"enabled": true, "services": []string{"BeyondPreviewService"}, "expectedRevision": 0, "source": f.sampleComplete.Source}
}
func TestCompleteServiceHealthRecorderSelectionAndMonitor(t *testing.T) {
	h, f, op, _ := completeHealthHandlerFixture(t)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete"
	w := completeServiceRequest(h, op, "GET", path, nil)
	var view windowsservicehealth.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.SchemaVersion != windowsservicehealth.CompleteSchemaVersion || view.Policy.Enabled || view.Inventory == nil || len(view.Inventory.Services) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = completeServiceRequest(h, op, "POST", path+"/policy", completeServiceBody(f)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	start := f.now
	for i := 0; i <= 6; i++ {
		f.now = start.Add(time.Duration(i) * 30 * time.Second)
		if i == 6 {
			p := &f.sampleComplete.Source
			p.Sequence++
			p.CapturedAt = f.now
			p.CaptureFinishedAt = f.now
			p.ReceivedAt = f.now
			p.ExpiresAt = f.now.Add(24 * time.Hour)
			p.GenerationID, _ = windowsfullservices.GenerationID(f.inputs[0].DeviceID, p.GrantID, p.Sequence)
		}
		before := f.reads
		if e := h.app.windowsCapacity.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
		if f.reads != before+1 {
			t.Fatal("competing source pass")
		}
	}
	w = completeServiceRequest(h, op, "GET", path, nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Status != "attention" || len(view.Incidents) != 1 || view.Checks[0].Observation.Source == nil || view.Checks[0].Observation.Sequence != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = completeServiceRequest(h, op, "GET", strings.TrimSuffix(path, "/complete"), nil); w.Code != 409 {
		t.Fatal("legacy route returned a v2 policy", w.Code)
	}
}
func TestCompleteServiceHealthRecorderAuthorityAndClosedRequests(t *testing.T) {
	for _, mode := range []string{"tampered-source", "missing-source", "csrf", "origin", "revoked", "grant", "source-age", "session", "legacy-body"} {
		t.Run(mode, func(t *testing.T) {
			h, f, op, _ := completeHealthHandlerFixture(t)
			path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete/policy"
			body := completeServiceBody(f)
			live := true
			op.active = func() bool { return live }
			if mode == "tampered-source" {
				p := f.sampleComplete.Source
				p.ManifestSHA256 = strings.Repeat("e", 64)
				body["source"] = p
			}
			if mode == "missing-source" {
				body["source"] = nil
			}
			if mode == "legacy-body" {
				delete(body, "source")
			}
			if mode == "source-age" {
				p := &f.sampleComplete.Source
				p.CapturedAt = p.CapturedAt.Add(-299 * time.Second)
				p.CaptureFinishedAt = p.CapturedAt
				p.ReceivedAt = p.CapturedAt
				p.ExpiresAt = p.CapturedAt.Add(24 * time.Hour)
				body["source"] = *p
			}
			f.onGuard = func(n int) {
				if n != 3 {
					return
				}
				switch mode {
				case "revoked":
					f.inputs[0].Authorized = false
				case "grant":
					f.sampleComplete.Source.GrantRevision++
				case "source-age":
					f.now = f.now.Add(2 * time.Second)
				case "session":
					live = false
				}
			}
			w := completeServiceRequest(h, op, "POST", path, body, func(r *http.Request) {
				if mode == "csrf" {
					r.Header.Del("X-CSRF-Token")
				}
				if mode == "origin" {
					r.Header.Set("Origin", "https://other.invalid")
				}
			})
			if w.Code == 200 {
				t.Fatal(mode, "accepted")
			}
			states, e := h.app.store.WindowsServiceStates(context.Background())
			if e != nil || len(states) != 0 {
				t.Fatal("failed guard persisted policy", e)
			}
		})
	}
}
func TestCompleteGroupServiceHealthRecorderReviewAndFixture(t *testing.T) {
	h, f, op, path := completeHealthHandlerFixture(t)
	v := groupServiceRead(t, h, op, path)
	if v.SchemaVersion != "tracebolt.fleet-group-service-checks.v2" || len(v.Members) != 1 {
		t.Fatal(v)
	}
	detail := path + "/" + v.Members[0].Key
	w := groupServiceRequest(h, op, "GET", detail, nil)
	var choice fleetGroupServiceChoiceView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &choice) != nil || choice.SchemaVersion != "tracebolt.fleet-group-service-choice.v2" || choice.Member.Inventory == nil || choice.Member.Inventory.Source == nil || len(choice.Member.Inventory.Services) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	var initial fleetGroupServiceChoiceView
	if err := json.Unmarshal(w.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	body := completeServiceBody(f)
	body["groupRevision"] = v.GroupRevision
	body["consent"] = true
	w = groupServiceRequest(h, op, "POST", detail, body)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &choice) != nil || choice.Member.Policy.Source == nil || !choice.Member.Policy.Enabled || len(choice.Member.Inventory.Services) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = groupServiceRequest(h, op, "POST", detail, body); w.Code != 409 {
		t.Fatal("replay accepted", w.Code)
	}
	if os.Getenv("TRACEBOLT_WRITE_COMPLETE_SERVICE_FIXTURE") == "1" {
		raw, e := json.MarshalIndent(map[string]any{"overview": v, "choice": initial, "configured": choice}, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile("../../web/src/windows-complete-group-service-go-fixture.json", append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
