package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/analysis"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type proactiveFake struct {
	call func(context.Context, analysis.ProviderRequest) ([]byte, error)
}

func (proactiveFake) Identity() analysis.ProviderIdentity {
	return analysis.ProviderIdentity{Name: "fixture", Model: "fixture-model", Destination: "test-only", EndpointOrigin: "http://127.0.0.1:11434"}
}
func (p proactiveFake) Generate(ctx context.Context, r analysis.ProviderRequest) ([]byte, error) {
	return p.call(ctx, r)
}
func proactiveSettings(t *testing.T, o operatorFixture) map[string]any {
	t.Helper()
	res, v := o.call(t, "GET", "/api/ai/proactive", nil, "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, v)
	}
	return v
}
func proactiveEnable(t *testing.T, o operatorFixture, csrf, id string) {
	t.Helper()
	v := proactiveSettings(t, o)
	body := map[string]any{"expectedRevision": v["revision"], "configRevision": v["configRevision"], "enabled": true, "deviceIds": []string{id}, "approvedBaseURL": v["baseURL"], "approvedModel": v["model"], "dataScope": "health-summary-v1", "acknowledgeData": true}
	res, b := o.call(t, "POST", "/api/ai/proactive", body, csrf, nil)
	if res.StatusCode != 200 || b["enabled"] != true {
		t.Fatal(res.StatusCode, b)
	}
}
func setProactiveFixtureProvider(o operatorFixture, call func(context.Context, analysis.ProviderRequest) ([]byte, error)) {
	o.app.ai.mu.Lock()
	defer o.app.ai.mu.Unlock()
	o.app.ai.config.Configured = true
	o.app.ai.config.Model = "fixture-model"
	o.app.ai.service = analysis.NewService(proactiveFake{call: call})
}
func seedProactiveIncident(t *testing.T, o operatorFixture, source *investigationsSource) {
	t.Helper()
	value := 95.0
	start := source.now
	for i := 0; i <= 4; i++ {
		at := start.Add(time.Duration(i) * 30 * time.Second)
		source.now = at
		source.inputs[0].ReceivedAt = at
		source.inputs[0].Disk = model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: at}
		if err := o.app.health.evaluate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

const proactiveFindings = `{"observedEvidenceIDs":["health-event","health-snapshot"],"hypotheses":[{"statement":"Die Belegung könnte steigen; Ursache offen.","evidenceIDs":["health-snapshot"]}],"counterevidence":[],"missingData":["Logs wurden nicht gesucht."],"nextCheck":"storage"}`

func TestProactiveAIExplicitScopeRunsOnceWithoutBrowserAndPersists(t *testing.T) {
	o, source := investigationsFixture(t)
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	id := source.inputs[0].DeviceID
	calls := 0
	setProactiveFixtureProvider(o, func(ctx context.Context, r analysis.ProviderRequest) ([]byte, error) {
		calls++
		if strings.Contains(r.Messages[1].Content, id) {
			t.Fatal("device ID exported")
		}
		return []byte(proactiveFindings), nil
	})
	if proactiveSettings(t, o)["enabled"] != false {
		t.Fatal("not default off")
	}
	if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil || calls != 0 {
		t.Fatal("default contacted provider", err)
	}
	proactiveEnable(t, o, csrf, id)
	if calls != 0 {
		t.Fatal("save contacted provider")
	}
	seedProactiveIncident(t, o, source)
	if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("background run absent")
	}
	if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil || calls != 1 {
		t.Fatal("duplicate run", err)
	}
	res, v := o.call(t, "GET", "/api/investigations", nil, "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, v)
	}
	item := v["items"].([]any)[0].(map[string]any)
	saved := item["analysis"].(map[string]any)
	if saved["status"] != "completed" || saved["result"].(map[string]any)["rootCauseConfirmed"] != false {
		t.Fatal(saved)
	}
	if calls != 1 {
		t.Fatal("GET caused inference")
	}
	if path := os.Getenv("TRACEBOLT_PROACTIVE_FIXTURE"); path != "" {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Original manual managed export still fails closed, even with proactive approval.
	o.app.aiCollectionProfile = "managed-operations-v1"
	res, _ = o.call(t, "POST", "/api/cases/case-demo-win-01-service/analyze", map[string]string{"configRevision": o.app.ai.config.Revision}, csrf, nil)
	if res.StatusCode != 403 {
		t.Fatal("manual managed export relaxed")
	}
}
func TestProactiveAIRequiresExactApprovalAndSkipsHistoricalIncidents(t *testing.T) {
	o, source := investigationsFixture(t)
	res, _ := o.call(t, "GET", "/api/ai/proactive", nil, "", nil)
	if res.StatusCode != 401 {
		t.Fatal("unauthenticated settings")
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	id := source.inputs[0].DeviceID
	calls := 0
	setProactiveFixtureProvider(o, func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		calls++
		return []byte(proactiveFindings), nil
	})
	v := proactiveSettings(t, o)
	base := map[string]any{"expectedRevision": v["revision"], "configRevision": v["configRevision"], "enabled": true, "deviceIds": []string{id}, "approvedBaseURL": v["baseURL"], "approvedModel": v["model"], "dataScope": "health-summary-v1", "acknowledgeData": true}
	for field, value := range map[string]any{"approvedBaseURL": "https://other.invalid/v1", "approvedModel": "other", "acknowledgeData": false, "dataScope": "raw-logs-v1", "deviceIds": []string{investigationDevice(99)}, "expectedRevision": "cfg-old"} {
		t.Run(field, func(t *testing.T) {
			body := map[string]any{}
			for k, v := range base {
				body[k] = v
			}
			body[field] = value
			res, _ := o.call(t, "POST", "/api/ai/proactive", body, csrf, nil)
			if res.StatusCode < 400 {
				t.Fatal("bad approval accepted")
			}
		})
	}
	res, _ = o.call(t, "POST", "/api/ai/proactive", base, "", nil)
	if res.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	seedProactiveIncident(t, o, source)
	source.now = source.now.Add(time.Second)
	proactiveEnable(t, o, csrf, id)
	if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil || calls != 0 {
		t.Fatal("history exported", err)
	}
}
func TestProactiveAIDisableProviderChangeAndRevocationDiscardResults(t *testing.T) {
	for _, mode := range []string{"disable", "provider-change", "revocation", "error"} {
		t.Run(mode, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			id := source.inputs[0].DeviceID
			setProactiveFixtureProvider(o, func(ctx context.Context, r analysis.ProviderRequest) ([]byte, error) {
				switch mode {
				case "disable":
					v := proactiveSettings(t, o)
					body := map[string]any{"expectedRevision": v["revision"], "configRevision": v["configRevision"], "enabled": false, "deviceIds": []string{}, "approvedBaseURL": "", "approvedModel": "", "dataScope": "health-summary-v1", "acknowledgeData": false}
					res, _ := o.call(t, "POST", "/api/ai/proactive", body, csrf, nil)
					if res.StatusCode != 200 {
						t.Fatal(res.StatusCode)
					}
				case "provider-change":
					res, _ := o.call(t, "POST", "/api/ai/config/clear", map[string]string{"expectedRevision": o.app.ai.config.Revision}, csrf, nil)
					if res.StatusCode != 200 {
						t.Fatal(res.StatusCode)
					}
				case "revocation":
					source.inputs[0].Authorized = false
				case "error":
					return nil, analysis.ErrUnavailable
				}
				return []byte(proactiveFindings), nil
			})
			proactiveEnable(t, o, csrf, id)
			seedProactiveIncident(t, o, source)
			if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil {
				t.Fatal(err)
			}
			all, err := o.app.store.HealthAnalyses(context.Background(), id)
			if err != nil || len(all) != 1 {
				t.Fatal(err, all)
			}
			for _, saved := range all {
				if mode == "error" {
					if saved.Status != "unavailable" || saved.Result == nil || saved.Result.AI.Findings != nil {
						t.Fatal(saved)
					}
				} else if saved.Status != "canceled" || saved.Result != nil {
					t.Fatal("superseded results retained", saved)
				}
			}
			if mode == "provider-change" && proactiveSettings(t, o)["enabled"] != false {
				t.Fatal("provider change kept approval")
			}
		})
	}
}
func TestProactiveAINoDevelopmentGrantAndBoundedPublicSettings(t *testing.T) {
	s := setup(t)
	w := request(s, "GET", "/api/ai/proactive", "", nil)
	if w.Code != http.StatusNotFound {
		t.Fatal(w.Code)
	}
	o, source := investigationsFixture(t)
	_, _ = o.login(t)
	v := proactiveSettings(t, o)
	raw, _ := json.Marshal(v)
	if v["logsAllowed"] != false || v["resetsOnRestart"] != true || strings.Contains(string(raw), "apiKey") || source.calls == 0 {
		t.Fatal("scope disclosure", v)
	}
}

func TestProactiveAIDisableDoesNotDependOnHealthSource(t *testing.T) {
	o, source := investigationsFixture(t)
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	id := source.inputs[0].DeviceID
	started := make(chan struct{})
	setProactiveFixtureProvider(o, func(ctx context.Context, _ analysis.ProviderRequest) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	proactiveEnable(t, o, csrf, id)
	seedProactiveIncident(t, o, source)
	settings := proactiveSettings(t, o)
	done := make(chan error, 1)
	go func() { done <- o.app.runProactiveAI(context.Background(), o.app.health) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider never started")
	}
	// A blocked provider holds neither the health mutex nor its evaluation loop.
	evaluated := make(chan error, 1)
	go func() { evaluated <- o.app.health.evaluate(context.Background()) }()
	select {
	case err := <-evaluated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("model stalled health evaluation")
	}
	o.app.health.mu.Lock()
	source.err = errors.New("fixture source unavailable")
	o.app.health.mu.Unlock()
	body := map[string]any{"expectedRevision": settings["revision"], "configRevision": settings["configRevision"], "enabled": false, "deviceIds": []string{}, "approvedBaseURL": "", "approvedModel": "", "dataScope": "health-summary-v1", "acknowledgeData": false}
	response, view := o.call(t, "POST", "/api/ai/proactive", body, csrf, nil)
	if response.StatusCode != 200 || view["enabled"] != false {
		t.Fatal("cannot disable after source failure", response.StatusCode, view)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disable did not cancel")
	}
}
func TestProactiveAINamedReadCannotApproveScope(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	source := &investigationsSource{now: time.Now().UTC(), inputs: []health.Input{{DeviceID: investigationDevice(1), Authorized: true}}}
	o.app.health = &healthMonitor{store: o.app.store, source: source}
	_, view := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	response, _ := o.call(t, "GET", "/api/ai/proactive", nil, "", nil)
	if response.StatusCode != 200 {
		t.Fatal("named settings read denied")
	}
	response, _ = o.call(t, "POST", "/api/ai/proactive", map[string]any{}, view["csrfToken"].(string), nil)
	if response.StatusCode != 403 {
		t.Fatal("named account granted export")
	}
}

func TestProactiveAIRechecksAuthorityAndElapsedAdmissionBeforeExport(t *testing.T) {
	for _, mode := range []string{"revoke", "expire", "elapsed", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			id := source.inputs[0].DeviceID
			calls := 0
			setProactiveFixtureProvider(o, func(context.Context, analysis.ProviderRequest) ([]byte, error) {
				calls++
				return []byte(proactiveFindings), nil
			})
			proactiveEnable(t, o, csrf, id)
			seedProactiveIncident(t, o, source)
			source.calls = 0
			source.change = func(n int) {
				if n == 2 {
					switch mode {
					case "revoke":
						source.inputs[0].Authorized = false
					case "expire":
						source.inputs[0].AuthorityUntil = source.now
					case "elapsed":
						time.Sleep(30 * time.Millisecond)
					case "rollback":
						source.now = source.now.Add(-time.Second)
					}
				}
			}
			if mode == "elapsed" {
				source.inputs[0].AuthorityUntil = source.now.Add(10 * time.Millisecond)
			}
			if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil {
				t.Fatal(err)
			}
			if calls != 0 {
				t.Fatal("authority changed during admission but bytes exported")
			}
			saved, err := o.app.store.HealthAnalyses(context.Background(), id)
			if err != nil || len(saved) != 1 {
				t.Fatal(saved, err)
			}
			for _, record := range saved {
				if record.Status != "canceled" || record.Result != nil {
					t.Fatal(record)
				}
			}
		})
	}
}

func TestProactiveAIFinalAuthorityReadMustRemainCurrent(t *testing.T) {
	for _, mode := range []string{"expiry-during-read", "duplicate-authority", "clock-rollback"} {
		t.Run(mode, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			id := source.inputs[0].DeviceID
			calls := 0
			setProactiveFixtureProvider(o, func(context.Context, analysis.ProviderRequest) ([]byte, error) {
				calls++
				return []byte(proactiveFindings), nil
			})
			proactiveEnable(t, o, csrf, id)
			seedProactiveIncident(t, o, source)
			source.calls = 0
			source.inputs[0].AuthorityUntil = source.now.Add(time.Minute)
			source.change = func(n int) {
				if n == 3 {
					switch mode {
					case "expiry-during-read":
						source.inputs[0].AuthorityUntil = source.now.Add(500 * time.Millisecond)
						source.now = source.now.Add(time.Second)
					case "duplicate-authority":
						source.inputs = append(source.inputs, source.inputs[0])
					case "clock-rollback":
						source.now = source.now.Add(-time.Second)
					}
				}
			}
			if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal("expected exactly the initial fixture model call")
			}
			saved, err := o.app.store.HealthAnalyses(context.Background(), id)
			if err != nil || len(saved) != 1 {
				t.Fatal(saved, err)
			}
			for _, record := range saved {
				if record.Status != "canceled" || record.Result != nil {
					t.Fatal("stale authority published result", record)
				}
			}
		})
	}
}
