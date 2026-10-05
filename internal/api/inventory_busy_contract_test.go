package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Pin the exact production backpressure response consumed by the native GET
// client. This does not change authorization, admission or any retained data.
func TestInventoryMaintenanceBusyResponseContract(t *testing.T) {
	for name, reply := range map[string]func(http.ResponseWriter, error){"packages": completeInventoryError, "overview": completeOverviewError, "system": systemInventoryError} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			reply(w, enrollmentstore.ErrInventoryBusy)
			var body struct {
				Error struct{ Code, Message string }
			}
			if w.Code != 429 || w.Header().Get("Retry-After") != "2" || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error.Code != "storage_busy" || body.Error.Message == "" || w.Body.Len() > 4096 {
				t.Fatal("production maintenance backpressure contract changed")
			}
		})
	}
}
