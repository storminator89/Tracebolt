package windowsfullsoftware

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFleetHistoryQueryPreservesLegacyShapeAndRejectsOtherModes(t *testing.T) {
	old := FleetQuery{Name: "Example", Version: "1", Cursor: ""}
	raw, e := json.Marshal(old)
	if e != nil || string(raw) != `{"name":"Example","version":"1","cursor":""}` {
		t.Fatal("old bytes", string(raw), e)
	}
	for _, q := range []FleetQuery{{View: "history"}, {View: "history", Name: "<[] 東京 2.0"}} {
		if ValidateFleetQuery(q) != nil {
			t.Fatal("private history search rejected", q)
		}
	}
	for _, q := range []FleetQuery{{View: "history", Version: "2"}, {View: "alerts", Name: "Example"}, {View: "history", Name: strings.Repeat("x", 257)}, {}} {
		if ValidateFleetQuery(q) == nil {
			t.Fatal("invalid mode/query", q)
		}
	}
}
