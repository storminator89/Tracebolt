package api

import (
	"context"
	"fmt"
	"localrmm/internal/analysis"
	"localrmm/internal/applicationcheck"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkReviewSessionBindingSingleUseAndDataBoundary(t *testing.T) {
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	at := time.Now().UTC().Add(-time.Second)
	state := "network_error"
	reason := "tcp_failed"
	generation := "generation-a"
	h.networkReviewFixture = func() (applicationcheck.View, string, bool) {
		return applicationcheck.View{Enabled: true, Vantage: "management_server", ServerNow: time.Now().UTC(), MaxAgeSeconds: 120, Items: []applicationcheck.Result{{ID: "private-target", Kind: "tcp", State: state, Reason: reason, ObservedAt: &at}}}, generation, true
	}
	var calls atomic.Int32
	setProactiveFixtureProvider(o, func(_ context.Context, req analysis.ProviderRequest) ([]byte, error) {
		calls.Add(1)
		if strings.Contains(req.Messages[1].Content, "private-target") || strings.Contains(req.Messages[1].Content, "10.47.1.151") {
			t.Error("target leaked")
		}
		return []byte(`{"observedEvidenceIDs":["network-check"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"network"}`), nil
	})
	if r, _ := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "private-target"}, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous review accepted")
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	if r, _ := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "private-target"}, "", nil); r.StatusCode != 403 {
		t.Fatal("CSRF-free review accepted")
	}
	preview := func() map[string]any {
		r, v := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "private-target"}, csrf, nil)
		if r.StatusCode != 200 {
			t.Fatal("preview", r.StatusCode, v)
		}
		return v
	}
	runBody := func(v map[string]any) map[string]any {
		return map[string]any{"checkId": "private-target", "snapshotToken": v["snapshotToken"], "configRevision": v["configRevision"], "acknowledge": true}
	}
	p := preview()
	validUntil, parseErr := time.Parse(time.RFC3339Nano, p["validUntil"].(string))
	if parseErr != nil || validUntil.After(at.Add(120*time.Second)) || validUntil.After(time.Now().Add(2*time.Minute)) {
		t.Fatal("preview extended its deadline")
	}
	if calls.Load() != 0 || p["kind"] != "tcp" || p["reason"] != "tcp_failed" {
		t.Fatal("bad preview")
	}
	body := runBody(p)
	bad := runBody(p)
	bad["acknowledge"] = false
	if r, _ := o.call(t, "POST", "/api/ai/network-review/run", bad, csrf, nil); r.StatusCode != 400 {
		t.Fatal("unconfirmed run")
	}
	if r, v := o.call(t, "POST", "/api/ai/network-review/run", body, csrf, nil); r.StatusCode != 200 || v["schemaVersion"] != "tracebolt.ai-network-review-result.v1" || calls.Load() != 1 {
		t.Fatal("run", r.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", "/api/ai/network-review/run", body, csrf, nil); r.StatusCode != 409 || calls.Load() != 1 {
		t.Fatal("replay")
	}
	p = preview()
	body = runBody(p)
	generation = "generation-b"
	if r, _ := o.call(t, "POST", "/api/ai/network-review/run", body, csrf, nil); r.StatusCode != 409 || calls.Load() != 1 {
		t.Fatal("source change accepted")
	}
	p = preview()
	body = runBody(p)
	_, other := o.login(t)
	otherCSRF := other["csrfToken"].(string)
	if r, _ := o.call(t, "POST", "/api/ai/network-review/run", body, otherCSRF, nil); r.StatusCode != 409 || calls.Load() != 1 {
		t.Fatal("cross-session accepted")
	}
	csrf = otherCSRF
	state = "unknown"
	reason = "stale"
	if r, _ := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "private-target"}, csrf, nil); r.StatusCode != 409 || calls.Load() != 1 {
		t.Fatal("stale preview")
	}
}

func TestNetworkReviewInFlightChangesAndSingleUse(t *testing.T) {
	for _, change := range []string{"source", "provider", "none"} {
		t.Run(change, func(t *testing.T) {
			o := newOperatorFixture(t, 0)
			h := o.server.Config.Handler.(*operatorHandler)
			at := time.Now().UTC().Add(-time.Second)
			var generation atomic.Int32
			h.networkReviewFixture = func() (applicationcheck.View, string, bool) {
				return applicationcheck.View{Enabled: true, Vantage: "management_server", ServerNow: time.Now().UTC(), MaxAgeSeconds: 120, Items: []applicationcheck.Result{{ID: "fixture", Kind: "dns", State: "ok", Reason: "dns_resolved", ObservedAt: &at}}}, string(rune('a' + generation.Load())), true
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			setProactiveFixtureProvider(o, func(ctx context.Context, _ analysis.ProviderRequest) ([]byte, error) {
				if calls.Add(1) == 1 {
					close(entered)
					select {
					case <-resume:
					case <-ctx.Done():
					}
				}
				return []byte(`{"observedEvidenceIDs":["network-check"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"network"}`), nil
			})
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			r, p := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "fixture"}, csrf, nil)
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode)
			}
			body := map[string]any{"checkId": "fixture", "snapshotToken": p["snapshotToken"], "configRevision": p["configRevision"], "acknowledge": true}
			_, otherPreview := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "fixture"}, csrf, nil)
			otherBody := map[string]any{"checkId": "fixture", "snapshotToken": otherPreview["snapshotToken"], "configRevision": otherPreview["configRevision"], "acknowledge": true}
			done := make(chan int, 1)
			go func() {
				response, _ := o.call(t, "POST", "/api/ai/network-review/run", body, csrf, nil)
				done <- response.StatusCode
			}()
			<-entered
			if response, _ := o.call(t, "POST", "/api/ai/network-review/run", body, csrf, nil); response.StatusCode != 409 {
				t.Fatal("parallel duplicate accepted")
			}
			if response, _ := o.call(t, "POST", "/api/ai/network-review/run", otherBody, csrf, nil); response.StatusCode != 409 {
				t.Fatal("independent busy review accepted")
			}
			if change == "source" {
				generation.Store(1)
			} else if change == "provider" {
				o.app.ai.mu.Lock()
				o.app.ai.config.Revision = "changed"
				o.app.ai.mu.Unlock()
			}
			close(resume)
			status := <-done
			if change == "none" {
				if status != 200 || calls.Load() != 1 {
					t.Fatal("current result rejected", status)
				}
				if response, _ := o.call(t, "POST", "/api/ai/network-review/run", otherBody, csrf, nil); response.StatusCode != 200 || calls.Load() != 2 {
					t.Fatal("busy consumed unused permit")
				}
			} else if status != 409 || calls.Load() != 1 {
				t.Fatal("stale result exposed", status, calls.Load())
			}
			if response, _ := o.call(t, "POST", "/api/ai/network-review/run", body, csrf, nil); response.StatusCode != 409 || calls.Load() != 1 {
				if change != "none" || response.StatusCode != 409 || calls.Load() != 2 {
					t.Fatal("consumed review replayed")
				}
			}
		})
	}
}

func TestNetworkReviewInvalidAnswerAndExpiredPermit(t *testing.T) {
	o := newOperatorFixture(t, 0)
	h := o.server.Config.Handler.(*operatorHandler)
	at := time.Now().UTC().Add(-time.Second)
	h.networkReviewFixture = func() (applicationcheck.View, string, bool) {
		return applicationcheck.View{Enabled: true, Vantage: "management_server", ServerNow: time.Now().UTC(), MaxAgeSeconds: 120, Items: []applicationcheck.Result{{ID: "fixture", Kind: "dns", State: "ok", Reason: "dns_resolved", ObservedAt: &at}}}, "generation", true
	}
	var calls atomic.Int32
	panicProvider := false
	setProactiveFixtureProvider(o, func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		calls.Add(1)
		if panicProvider {
			panic("private-panic-canary")
		}
		return []byte(`{"unexpected":"private-model-output"}`), nil
	})
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	preview := func() map[string]any {
		r, p := o.call(t, "POST", "/api/ai/network-review/preview", map[string]any{"checkId": "fixture"}, csrf, nil)
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode)
		}
		return p
	}
	body := func(p map[string]any) map[string]any {
		return map[string]any{"checkId": "fixture", "snapshotToken": p["snapshotToken"], "configRevision": p["configRevision"], "acknowledge": true}
	}
	p := preview()
	r, v := o.call(t, "POST", "/api/ai/network-review/run", body(p), csrf, nil)
	if r.StatusCode != 200 || calls.Load() != 1 {
		t.Fatal("invalid-answer response", r.StatusCode)
	}
	result, ok := v["result"].(map[string]any)
	if !ok {
		t.Fatal("missing result")
	}
	ai, ok := result["ai"].(map[string]any)
	if !ok || ai["status"] != "invalid_response" || ai["findings"] != nil {
		t.Fatal("invalid model response shown")
	}
	if r, _ := o.call(t, "POST", "/api/ai/network-review/run", body(p), csrf, nil); r.StatusCode != 409 {
		t.Fatal("invalid attempt replayed")
	}
	p = preview()
	token := p["snapshotToken"].(string)
	o.app.ai.mu.Lock()
	permit := o.app.ai.networkReviews[token]
	permit.Until = time.Now().Add(-time.Second)
	o.app.ai.networkReviews[token] = permit
	o.app.ai.mu.Unlock()
	if r, _ := o.call(t, "POST", "/api/ai/network-review/run", body(p), csrf, nil); r.StatusCode != 409 || calls.Load() != 1 {
		t.Fatal("expired permit used")
	}
	panicProvider = true
	p = preview()
	r, v = o.call(t, "POST", "/api/ai/network-review/run", body(p), csrf, nil)
	result, ok = v["result"].(map[string]any)
	if !ok {
		t.Fatal("missing unavailable result")
	}
	ai, ok = result["ai"].(map[string]any)
	if r.StatusCode != 200 || !ok || ai["status"] != "unavailable" || ai["findings"] != nil || strings.Contains(fmt.Sprint(v), "private-panic-canary") || calls.Load() != 2 {
		t.Fatal("provider panic leaked or counted incorrectly")
	}
	if r, _ = o.call(t, "POST", "/api/ai/network-review/run", body(p), csrf, nil); r.StatusCode != 409 {
		t.Fatal("panicking attempt replayed")
	}
	o.app.ai.mu.Lock()
	busy := o.app.ai.busy
	o.app.ai.mu.Unlock()
	if busy {
		t.Fatal("provider panic leaked global slot")
	}
}
