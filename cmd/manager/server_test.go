package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"localrmm/internal/analysis"
	"localrmm/internal/api"
	"localrmm/internal/fixtures"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPWriteBudgetOutlastsAnalysis(t *testing.T) {
	server := newHTTPServer(http.NotFoundHandler())
	if server.WriteTimeout <= analysis.MaxTimeout {
		t.Fatal("manager write deadline cannot return bounded analysis outcomes")
	}
}

// This intentionally crosses the former 10-second write deadline over real TCP.
// Fake provider only; no credentials or external calls are used.
func TestRealManagerReturnsDelayedFakeProviderResult(t *testing.T) {
	if testing.Short() {
		t.Skip("real TCP delayed-provider integration")
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(11 * time.Second):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		content := `{"observedEvidenceIDs":["demo-win-01-service-state"],"hypotheses":[],"counterevidence":[],"missingData":["Weitere Evidenz erforderlich."],"nextCheck":"service"}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}})
	}))
	defer provider.Close()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal("test database could not open")
	}
	defer db.Close()
	devices, cases := fixtures.Seed(time.Now())
	if err = db.Seed(devices, cases); err != nil {
		t.Fatal("fixture seed failed")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("local test listener unavailable")
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	handler, err := api.New(db, port, t.TempDir(), model.Device{ID: "sandbox-local", Source: "sandbox", Status: "unknown"})
	if err != nil {
		t.Fatal("test handler construction failed")
	}
	server := newHTTPServer(handler)
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 25 * time.Second}
	call := func(method, path string, body any, token string) map[string]any {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		request, err := http.NewRequest(method, base+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal("test request construction failed")
		}
		if method == "POST" {
			request.Header.Set("Origin", base)
			request.Header.Set("X-CSRF-Token", token)
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("real HTTP request failed; no response received")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("real HTTP request returned unexpected status", response.StatusCode)
		}
		var value map[string]any
		if json.NewDecoder(response.Body).Decode(&value) != nil {
			t.Fatal("response JSON invalid")
		}
		return value
	}
	token := call("GET", "/api/session", nil, "")["csrfToken"].(string)
	revision := call("GET", "/api/ai/config", nil, "")["revision"].(string)
	saved := call("POST", "/api/ai/config", map[string]any{"expectedRevision": revision, "baseURL": provider.URL + "/v1", "model": "fixture-slow", "apiKey": "", "approvedOrigin": provider.URL, "allowRemoteEvidence": false, "useLegacyMaxTokens": false}, token)
	started := time.Now()
	result := call("POST", "/api/cases/case-demo-win-01-service/analyze", map[string]string{"configRevision": saved["revision"].(string)}, token)
	if time.Since(started) < 10*time.Second {
		t.Fatal("test did not cross old deadline")
	}
	ai, ok := result["ai"].(map[string]any)
	if !ok || ai["status"] != "completed" {
		t.Fatal("slow provider result was not returned successfully")
	}
}
