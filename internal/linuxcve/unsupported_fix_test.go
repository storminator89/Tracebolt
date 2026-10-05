package linuxcve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/linuxpackages"
	"strings"
	"testing"
)

type forbiddenVersionComparison struct{ calls int }

func (c *forbiddenVersionComparison) Compare(context.Context, string, string) (int, error) {
	c.calls++
	return -1, nil
}

func TestTrackerVersionTokensRemainUnassessedWithoutComparison(t *testing.T) {
	for _, version := range []string{"v1.2-3", "release:1.2-3", "1.2-", "~1.2-3", ":", strings.Repeat("a", 512)} {
		t.Run(version[:min(len(version), 20)], func(t *testing.T) {
			snapshot := parse(t, DebianProvider, debianPayload(version, "resolved"))
			if snapshot.rules["openssl"][0].fixed != "" || snapshot.rules["openssl"][0].reason != "vendor_fixed_version_unsupported" {
				t.Fatal("unsupported token became a fix")
			}
			m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1")}, testNow)
			comparator := &forbiddenVersionComparison{}
			result := Evaluate(context.Background(), snapshot, m, rows, comparator, testNow)
			if comparator.calls != 0 || len(result.Findings) != 0 || result.Status != "partial" || result.UnassessedRecordCount != 1 || result.EvaluatedSourceCount != 0 || !hasReason(result, "vendor_fixed_version_unsupported") {
				t.Fatalf("unsupported token produced a conclusion or hidden gap: %+v", result)
			}
		})
	}
}

func TestUnsupportedFixDoesNotDiscardSupportedRecordsOrDuplicateCounts(t *testing.T) {
	payload := `{"openssl":{"CVE-2026-1000":{"releases":{"trixie":{"status":"resolved","fixed_version":"v1.2-3"}}},"CVE-2026-1001":{"releases":{"trixie":{"status":"resolved","fixed_version":"3.0-1"}}}}}`
	snapshot := parse(t, DebianProvider, payload)
	a, b := row("libssl-one", "openssl", "1.0-1"), row("libssl-two", "openssl", "2.0-1")
	result := evaluate(t, snapshot, linuxpackages.Debian13, a, b)
	if len(result.Findings) != 2 || result.UnassessedRecordCount != 1 || result.EvaluatedSourceCount != 1 {
		t.Fatalf("mixed-source record accounting failed: %+v", result)
	}
	for _, finding := range result.Findings {
		if finding.CVEID != "CVE-2026-1001" || finding.PublishedFixedVersion != "3.0-1" {
			t.Fatal("unsupported advisory was matched")
		}
	}
}

func TestUnsupportedVersionFallbackDoesNotAdmitMalformedData(t *testing.T) {
	for _, version := range []string{"bad version", "v1/2", "v1_2", "<not-affected>", "<end-of-life>", "v1\n2", "v1\t2", "v1\x002", "v1é", strings.Repeat("a", 513)} {
		encoded, _ := json.Marshal(version)
		payload := strings.Replace(debianPayload("MARKER", "resolved"), `"MARKER"`, string(encoded), 1)
		if _, err := Parse(context.Background(), bytes.NewReader(bundle(t, DebianProvider, payload, testNow)), testNow); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed token admitted", err)
		}
	}
	wrongType := strings.Replace(debianPayload("0", "resolved"), `"fixed_version":"0"`, `"fixed_version":0`, 1)
	if _, err := Parse(context.Background(), bytes.NewReader(bundle(t, DebianProvider, wrongType, testNow)), testNow); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-string fixed version admitted", err)
	}
	zero := evaluate(t, parse(t, DebianProvider, debianPayload("0", "resolved")), linuxpackages.Debian13, row("openssl", "openssl", "1.0-1"))
	if len(zero.Findings) != 0 || zero.UnassessedRecordCount != 0 || zero.EvaluatedSourceCount != 1 {
		t.Fatal("not-affected zero semantics changed")
	}
}

func TestUnassessedRecordCounterIncludesKnownGapsAndIsZeroWithoutPrerequisites(t *testing.T) {
	for _, tc := range []struct{ status, fixed string }{{"open", ""}, {"undetermined", ""}, {"resolved", ""}} {
		result := evaluate(t, parse(t, DebianProvider, debianPayload(tc.fixed, tc.status)), linuxpackages.Debian13, row("openssl", "openssl", "1.0-1"))
		if result.UnassessedRecordCount != 1 || len(result.Findings) != 0 {
			t.Fatal("known gap was not counted")
		}
	}
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1")}, testNow)
	if result := Evaluate(context.Background(), nil, m, rows, nil, testNow); result.Status != "unavailable" || result.UnassessedRecordCount != 0 {
		t.Fatal("missing feed invented a record count")
	}
	result := Evaluate(context.Background(), parse(t, DebianProvider, debianPayload("2.0-1", "resolved")), m, rows, nil, testNow)
	if result.UnassessedRecordCount != 1 || len(result.Findings) != 0 || !hasReason(result, "debian_comparator_unavailable") {
		t.Fatal("unavailable comparison invented an assessed record")
	}
}
