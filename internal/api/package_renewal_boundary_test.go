package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"localrmm/internal/enrollmentstore"
)

func TestPackageUpdateRenewalUnsupportedIsExplicit(t *testing.T) {
	w := httptest.NewRecorder()
	packageUpdateError(w, enrollmentstore.ErrPackageRenewalUnsupported)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"package_update_renewal_unsupported"`) {
		t.Fatal("unsupported scope was hidden as ordinary unavailability", w.Code, w.Body.String())
	}
}
