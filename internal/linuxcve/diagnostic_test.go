package linuxcve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestInvalidDiagnosticsPreserveRejectionWithoutInputDisclosure(t *testing.T) {
	for _, tc := range []struct{ payload, code string }{
		{`[]`, "debian_root"},
		{`{}`, "target_scope_empty"},
		{`{"private/marker":{}}`, "debian_source_name"},
		{`{"private-marker":[]}`, "debian_source_records"},
		{`{"private-marker":{}}`, "debian_empty_source"},
		{`{"private-marker":{"CVE-2099-1000":[]}}`, "debian_issue"},
		{`{"private-marker":{"CVE-2099-1000":{}}}`, "debian_releases"},
		{`{"private-marker":{"CVE-2099-1000":{"releases":{"trixie":[]}}}}`, "debian_release"},
		{`{"private-marker":{"CVE-2099-1000":{"releases":{"trixie":{}}}}}`, "debian_status"},
		{`{"private-marker":{"CVE-2099-1000":{"releases":{"trixie":{"status":"resolved","fixed_version":"private marker"}}}}}`, "debian_fixed_version"},
		{`{"private-marker":{},"PRIVATE-MARKER":{}}`, "json_duplicate_key"},
		{"\xff", "json_utf8"},
	} {
		_, err := ParseOfficialDebianBytes(context.Background(), []byte(tc.payload), testNow, testNow)
		if !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
			t.Fatal("error contract changed", err)
		}
		code, items, depth, ok := InvalidDiagnostic(fmt.Errorf("wrapper: %w", err))
		if !ok || code != tc.code || items < 0 || items > 16000001 || depth < 0 || depth > 33 {
			t.Fatal("wrong bounded diagnostic", code, items, depth)
		}
		for _, text := range []string{fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), code} {
			if strings.Contains(text, "private") || strings.Contains(text, "CVE-") {
				t.Fatal("diagnostic exposed input")
			}
		}
	}
	for _, err := range []error{nil, ErrInvalid, ErrLimit, invalidAt(255, 0, 0), invalidAt(invalidJSONKey, -1, 0), invalidAt(invalidJSONKey, 0, 99)} {
		if _, _, _, ok := InvalidDiagnostic(err); ok {
			t.Fatal("invalid diagnostic escaped")
		}
	}
}
