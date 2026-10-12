package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedMSIOperatorRoutesClosed(t *testing.T) {
	device := "agent_" + strings.Repeat("1", 32)
	for _, suffix := range []string{"", "/reserve", "/upload", "/complete", "/deliver", "/review", "/approve", "/review-coordinated", "/retire", "/schedule", "/cancel-schedule"} {
		r := httptest.NewRequest("POST", "https://manager.test/api/devices/"+device+"/windows-managed-msi"+suffix, nil)
		got, op, ok := windowsManagedMSIRoute(r)
		if !ok || got != device || op != strings.TrimPrefix(suffix, "/") {
			t.Fatal(suffix)
		}
	}
	for _, suffix := range []string{"/download", "/filename/x.msi", "/install", "/reset", "/remove", "//upload", "/reschedule", "/retry", "/schedule/batch"} {
		r := httptest.NewRequest("POST", "https://manager.test/api/devices/"+device+"/windows-managed-msi"+suffix, nil)
		if _, _, ok := windowsManagedMSIRoute(r); ok {
			t.Fatal(suffix)
		}
	}
}
