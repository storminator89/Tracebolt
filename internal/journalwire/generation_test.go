package journalwire

import (
	"bytes"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"strings"
	"testing"
	"time"
)

func TestGenerationReportCanonicalBoundsAndV2Description(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	r := journalgeneration.Report{SchemaVersion: journalgeneration.ReportSchemaVersion, Tuple: journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}, Sequence: 1, ObservedAt: at}
	raw, err := EncodeGenerationReport(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeGenerationReport(raw); err != nil || !journalgeneration.EqualReport(got, r) {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(raw, '\n'), append(raw, raw...), []byte("null"), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), bytes.Replace(raw, []byte(`"observedAt":`), []byte(`"ObservedAt":`), 1), bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":"1","unit":"secret.service"`), 1), bytes.Repeat([]byte(" "), 4097)} {
		if _, err := DecodeGenerationReport(bad); err == nil {
			t.Fatal("ambiguous/unbounded report accepted")
		}
	}
	if BodyLimit(GenerationPath) != journalgeneration.MaxReportBytes || !validPath(GenerationPath) {
		t.Fatal("route bounds")
	}
	q := journalview.Query{Unit: "fixture.service", Start: at.Add(-time.Minute), End: at, MaxPriority: 3}
	created, err := journalrequest.NewWithGeneration("agent_"+strings.Repeat("a", 32), strings.Repeat("c", 64), 1, q, r.Tuple, at)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encode(created.Description, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeDescription(encoded); err != nil || decoded != created.Description {
		t.Fatal("v2 description decode", err)
	}
}
