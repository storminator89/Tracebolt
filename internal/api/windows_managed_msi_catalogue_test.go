package api

import (
	msi "localrmm/internal/windowsmanagedmsi"
	"net/http/httptest"
	"testing"
)

func TestManagedMSICatalogueGETPinsAndFixedRoutes(t *testing.T) {
	for _, tc := range []struct {
		path        string
		enabled, ok bool
		op          string
	}{{"?artifactRetiredCount=1", true, true, ""}, {"?artifactRetiredCount=1", false, false, ""}, {"", true, false, ""}, {"", false, true, ""}, {"?artifactRetiredCount=0", true, false, ""}, {"?artifactRetiredCount=01", true, false, ""}, {"?artifactRetiredCount=1&artifactRetiredCount=2", true, false, ""}, {"?artifactRetiredCount=%31", true, false, ""}, {"?artifactRetiredCount=1", true, false, "retire"}} {
		r := httptest.NewRequest("GET", "https://manager.invalid/api/windows-managed-msi/artifact"+tc.path, nil)
		w := httptest.NewRecorder()
		if got := pinWindowsMSICatalogueGET(w, &r, tc.enabled, tc.op); got != tc.ok {
			t.Fatalf("%+v got %v", tc, got)
		}
		if tc.ok && tc.enabled {
			if n, ok := msi.CatalogueOccurrence(r.Context()); !ok || n != 1 {
				t.Fatal("lost pin")
			}
		}
	}
	for _, p := range []string{"/api/windows-managed-msi/catalogue", "/api/windows-managed-msi/catalogue/reserve"} {
		if _, ok := windowsManagedMSICatalogueRoute(httptest.NewRequest("GET", p, nil)); !ok {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"/api/windows-managed-msi/catalogue/retire", "/api/windows-managed-msi/catalogue/1", "/api/windows-managed-msi/catalogue/", "/api/windows-managed-msi/catalogue/path/file"} {
		if _, ok := windowsManagedMSICatalogueRoute(httptest.NewRequest("GET", p, nil)); ok {
			t.Fatal(p)
		}
	}
}
