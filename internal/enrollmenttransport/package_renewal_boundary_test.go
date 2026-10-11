package enrollmenttransport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"localrmm/internal/enrollmentstore"
)

func TestPackageRenewalUnsupportedIsExplicit(t *testing.T) {
	w := httptest.NewRecorder()
	packageActionFailure(w, enrollmentstore.ErrPackageRenewalUnsupported)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"package_action_renewal_unsupported"`) {
		t.Fatal("unsupported scope was hidden as a storage failure", w.Code, w.Body.String())
	}
}
