package api

import (
	"context"
	"localrmm/internal/windowsmanagedmsimanager"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedMSIOccurrenceRequestPinsRequireCanonicalStrings(t *testing.T) {
	for _, value := range []string{"", "00", "-1", "+1", "18446744073709551616"} {
		request := httptest.NewRequest("POST", "https://manager.invalid/api/windows-managed-msi/artifact/complete", strings.NewReader(`{}`))
		response := httptest.NewRecorder()
		if pinManagedMSIArtifactOccurrence(response, &request, value) || response.Code != 400 {
			t.Fatalf("invalid floor %q accepted: %d", value, response.Code)
		}
	}
	for _, value := range []string{"0", "2", "18446744073709551615"} {
		request := httptest.NewRequest("POST", "https://manager.invalid/api/windows-managed-msi/artifact/complete", strings.NewReader(`{}`))
		response := httptest.NewRecorder()
		if !pinManagedMSIArtifactOccurrence(response, &request, value) {
			t.Fatalf("valid floor %q refused", value)
		}
	}
	if _, err := windowsmanagedmsimanager.WithArtifactReserveOccurrence(context.Background(), "0", "not-an-artifact"); err == nil {
		t.Fatal("malformed expected artifact accepted")
	}
}
