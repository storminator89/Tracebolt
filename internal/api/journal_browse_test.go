package api

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetainedCreateHasExplicitProtocolWithoutPerReadAcknowledgement(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	g := journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}
	q := journalview.Query{Unit: "fixture.service", Start: time.Unix(0, 0).UTC(), End: now, MaxPriority: 7, BrowseMode: journalview.BrowseMode, Search: "literal"}
	body := map[string]any{"expectedFloor": "0", "query": q, "acknowledgeLogContent": false, "acknowledgePlaintext": false, "expectedPolicyGeneration": g}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/api/devices/agent_fixture/journal/create", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	floor, got, expected, ok := readJournalCreate(w, r, now, true)
	if !ok || floor != 0 || got != q || expected != g {
		t.Fatal("explicit new protocol rejected before local grant check", w.Code)
	}
	delete(body, "expectedPolicyGeneration")
	raw, _ = json.Marshal(body)
	r = httptest.NewRequest("POST", "/api/devices/agent_fixture/journal/create", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	if _, _, _, ok := readJournalCreate(w, r, now, true); ok {
		t.Fatal("browse accepted without exact generation")
	}
}
func TestRetainedManagerCapabilitiesAreDistinctMetadata(t *testing.T) {
	h := &operatorHandler{authority: "127.0.0.1:8787", origin: "http://127.0.0.1:8787", insecureHTTPTest: true, enrollment: &enrollmentservice.Service{}, enrollmentBootstrap: downloadFixtureBootstrap()}
	r := httptest.NewRequest("GET", h.origin+journalBrowseCapabilitiesPath, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got) != 5 || got["request"] != journalrequest.SchemaVersionV3 || got["browsingContract"] != journalview.BrowseContract || got["generationReport"] != journalgeneration.ReportVersionV3 {
		t.Fatal("new metadata contract", w.Code)
	}
}
