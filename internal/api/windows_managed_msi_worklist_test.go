package api

import (
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedMSIWorklistRoutesAndStrictOptionalBatch(t *testing.T) {
	id := "worklist_" + strings.Repeat("a", 32)
	for _, suffix := range []string{"", "/save", "/" + id, "/" + id + "/preview", "/" + id + "/batches", "/" + id + "/close", "/" + id + "/archive"} {
		r := httptest.NewRequest("GET", "https://manager.test/api/windows-managed-msi/worklists"+suffix, nil)
		if _, _, ok := windowsMSIWorklistRoute(r); !ok {
			t.Fatal("fixed route rejected", suffix)
		}
	}
	for _, suffix := range []string{"/resume", "/" + id + "/dispatch", "/" + id + "/retry", "/" + id + "/close/again", "//save", "/worklist_00000000000000000000000000000000"} {
		r := httptest.NewRequest("POST", "https://manager.test/api/windows-managed-msi/worklists"+suffix, nil)
		if _, _, ok := windowsMSIWorklistRoute(r); ok {
			t.Fatal("extra route admitted", suffix)
		}
	}
	ref := msi.WorklistDispatchReference{WorklistID: id, BatchID: "batch_" + strings.Repeat("b", 32), Item: 0}
	raw, _ := json.Marshal(ref)
	for _, test := range []struct {
		name, body     string
		reusable, want bool
	}{
		{"legacy unchanged", `{"acknowledged":true}`, false, true},
		{"legacy not promoted", `{"acknowledged":true,"batch":` + string(raw) + `}`, false, false},
		{"reusable exact", `{"acknowledged":true,"batch":` + string(raw) + `}`, true, true},
		{"duplicate outer", `{"acknowledged":true,"acknowledged":true,"batch":` + string(raw) + `}`, true, false},
		{"null", `{"acknowledged":true,"batch":null}`, true, false},
		{"duplicate nested", `{"acknowledged":true,"batch":{"worklistId":"` + id + `","worklistId":"` + id + `","batchId":"` + ref.BatchID + `","item":0}}`, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var in struct {
				Acknowledged bool                           `json:"acknowledged"`
				Batch        *msi.WorklistDispatchReference `json:"batch,omitempty"`
			}
			r := httptest.NewRequest("POST", "https://manager.test/api/devices/agent_"+strings.Repeat("c", 32)+"/windows-managed-msi/deliver", strings.NewReader(test.body))
			w := httptest.NewRecorder()
			if got := readManagedMSIBatchObject(w, r, test.reusable, []string{"acknowledged"}, &in); got != test.want {
				t.Fatalf("accepted %v status %d", got, w.Code)
			}
		})
	}
}
