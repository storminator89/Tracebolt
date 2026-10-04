package api

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOperationalReadDefaultsAreExplicitAndBounded(t *testing.T) {
	s := setup(t)
	w := request(s, "GET", "/api/devices/demo-linux-01/operational", "", nil)
	if w.Code == 404 {
		w = request(s, "GET", "/api/devices/demo-win-01/operational", "", nil)
	}
	var v enrollmentstore.OperationalView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Status != "not_configured" || v.Snapshot != nil || v.Assessments.Updates.Quality != "unknown" {
		t.Fatal("implicit operational data or assessment")
	}
	if w = request(s, "GET", "/api/devices/unknown/operational", "", nil); w.Code != 404 {
		t.Fatal("unknown device exposed")
	}
}
func TestManagedSourcePolicyCannotBeRelabeledForAIExport(t *testing.T) {
	s := setup(t)
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); completion(w, fakeFindings()) }))
	defer provider.Close()
	config := configure(t, s, provider.URL+"/v1", "")
	for index, tag := range []string{"", "basic-readonly-v1", "managed-operations-v1"} {
		// The source policy comes from the trusted instance binding. Simulated case
		// labels do not participate in that authority decision.
		s.mu.Lock()
		s.aiCollectionProfile = "managed-operations-v1"
		s.mu.Unlock()
		cases, e := s.store.Cases()
		if e != nil {
			t.Fatal(e)
		}
		cases = cases[:1]
		cases[0].ID = fmt.Sprintf("case-profile-test-%d", index)
		cases[0].CollectionProfile = tag
		if e = s.store.Seed(nil, cases); e != nil {
			t.Fatal(e)
		}
		if w := request(s, "POST", "/api/cases/"+cases[0].ID+"/analyze", `{"configRevision":"`+config.Revision+`"}`, nil); w.Code != 403 {
			t.Fatal("managed source relabeled for export")
		}
	}
	s.store.Close()
	if w := analyze(t, s, config.Revision); w.Code != 403 {
		t.Fatal("case titles read before source policy rejection")
	}
	if calls.Load() != 0 {
		t.Fatal("provider called for managed source")
	}
}
