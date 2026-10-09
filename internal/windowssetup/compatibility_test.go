package windowssetup

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompatibilityExactAndNoExtensions(t *testing.T) {
	want := Expected("manager_00000000000000000000000000000001", "https://manager.example:8443", "https://manager.example:8444")
	raw, _ := json.Marshal(want)
	if Match(raw, want) != nil {
		t.Fatal("exact rejected")
	}
	for _, bad := range []string{"", string(raw) + "\n", string(raw) + string(raw), strings.Replace(string(raw), "fresh-five-read-scopes-v1", "fresh-five-read-scopes-v2", 1), strings.Replace(string(raw), "8444", "8445", 1), strings.Replace(string(raw), `"schemaVersion":`, `"schemaVersion":"duplicate","schemaVersion":`, 1), strings.Replace(string(raw), `"schemaVersion"`, `"SchemaVersion"`, 1), strings.TrimSuffix(string(raw), "}") + `,"extra":true}`} {
		if Match([]byte(bad), want) == nil {
			t.Fatal("incompatible accepted")
		}
	}
}
