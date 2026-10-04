package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPackageReadDefaultsAndProfileConsent(t *testing.T) {
	s := setup(t)
	w := request(s, "GET", "/api/devices/demo-linux-01/packages", "", nil)
	var view enrollmentstore.PackageView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Status != "not_configured" || view.Snapshot != nil {
		t.Fatal("implicit package observations")
	}
	if request(s, "GET", "/api/devices/unknown/packages", "", nil).Code != 404 {
		t.Fatal("unknown package device")
	}
	for _, path := range []string{"/api/devices/demo-linux-01/packages?x=1", "/api/devices/demo-linux-01/packages?"} {
		if request(s, "GET", path, "", nil).Code != 400 {
			t.Fatal("package query allowed")
		}
	}
	for _, body := range []string{`{"requestId":"fixture","platform":"linux"}`, `{"requestId":"fixture","platform":"linux","collectionAcknowledged":false}`} {
		r := httptest.NewRequest("POST", "/api/enrollment/invitations", strings.NewReader(body))
		out := httptest.NewRecorder()
		if _, ok := readInvitationInput(out, r, enrollmentcrypto.CollectionProfilePackages); ok {
			t.Fatal("package collection had no explicit consent")
		}
	}
	r := httptest.NewRequest("POST", "/api/enrollment/invitations", strings.NewReader(`{"requestId":"fixture","platform":"linux","collectionAcknowledged":true}`))
	out := httptest.NewRecorder()
	if _, ok := readInvitationInput(out, r, enrollmentcrypto.CollectionProfilePackages); !ok {
		t.Fatal("explicit package acknowledgement rejected")
	}
}
func TestPackageSourceRemainsUnassessedAndExcludedFromAI(t *testing.T) {
	s := setup(t)
	source := softwareCoverageFixture()
	s.mu.Lock()
	s.aiCollectionProfile = enrollmentcrypto.CollectionProfilePackages
	s.lanOperational = func(context.Context, string, time.Time) (enrollmentstore.OperationalView, error) { return source, nil }
	s.mu.Unlock()
	w := request(s, "GET", "/api/devices/demo-linux-01/security", "", nil)
	var view securityCoverageView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Vulnerabilities.AffectedCVEs != nil || view.Vulnerabilities.ReasonCodes[1] != "source_package_mapping_not_assessed" || view.Vulnerabilities.ReasonCodes[2] != "client_release_not_assessed" {
		t.Fatal("package facts became assessment verdicts")
	}
	s.store.Close()
	w = request(s, "POST", "/api/cases/demo-case-dns/analyze", `{"configRevision":"ignored"}`, nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "evidence_export_not_approved") {
		t.Fatal("package source read case text or reached provider before exclusion")
	}
}
