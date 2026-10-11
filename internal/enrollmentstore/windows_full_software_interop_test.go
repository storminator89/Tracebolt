package enrollmentstore

import (
	"encoding/json"
	"localrmm/internal/windowsfullsoftware"
	"strings"
	"testing"
)

// All labels and identities are invented fixture data. The typed SQLite output
// is exported for portable UI parsing/paging checks, never host acceptance.
func TestWindowsFullSoftwareExportInteropVectors(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	type vector struct {
		Name  string                    `json:"name"`
		Query windowsfullsoftware.Query `json:"query"`
		Page  windowsfullsoftware.Page  `json:"page"`
	}
	vectors := []vector{}
	at := f.at
	q := softwareQuery()
	failure := windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 1, AttemptedAt: &at, Reason: "access_denied"}
	if _, e := f.apply(t, failure, at); e != nil {
		t.Fatal(e)
	}
	vectors = append(vectors, vector{"unavailable", q, f.page(t, q, at)})
	for _, m := range f.messages(t, 2, 2051, at) {
		if _, e := f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
	p := f.page(t, q, at)
	vectors = append(vectors, vector{"first2051", q, p})
	for i := 0; i < 7; i++ {
		q.Cursor = p.NextCursor
		p = f.page(t, q, at)
	}
	if p.Offset != 700 || p.Rows[0].Name == nil || *p.Rows[0].Name != "InventedSoftware00700" {
		t.Fatal("late fixture offset")
	}
	vectors = append(vectors, vector{"offset700", q, p})
	q = softwareQuery()
	q.Search = "Firma 02049 東京"
	p = f.page(t, q, at)
	if p.MatchingCount != 1 {
		t.Fatal("late complete-generation search")
	}
	vectors = append(vectors, vector{"unicode2049", q, p})
	failure.Sequence = 3
	if _, e := f.apply(t, failure, at); e != nil {
		t.Fatal(e)
	}
	q = softwareQuery()
	vectors = append(vectors, vector{"priorCompleteLatestFailed", q, f.page(t, q, at)})
	f.capture(t, 4, []windowsfullsoftware.Row{
		softwareRow(1, softwareText("Duplicate 東京"), softwareText("1.0"), softwareText("Fixture publisher"), "32"),
		softwareRow(2, softwareText("Duplicate 東京"), softwareText("2.0"), softwareText("Fixture publisher"), "64"),
		softwareRow(3, nil, nil, nil, "64"),
		softwareRow(4, softwareText(""), softwareText(""), softwareText(""), "32"),
	})
	vectors = append(vectors, vector{"duplicatesMissing", q, f.page(t, q, at)})
	value := strings.Repeat("<", 512)
	rows := make([]windowsfullsoftware.Row, 128)
	for i := range rows {
		rows[i] = softwareRow(i+1, &value, &value, &value, "64")
	}
	f.capture(t, 5, rows)
	p = f.page(t, q, at)
	if len(p.Rows) == 0 || len(p.Rows) >= 100 || p.NextCursor == "" {
		t.Fatal("byte ceiling not reached")
	}
	vectors = append(vectors, vector{"byteShort", q, p})
	q.Cursor = p.NextCursor
	p = f.page(t, q, at)
	vectors = append(vectors, vector{"byteShortContinuation", q, p})
	raw, e := json.Marshal(vectors)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("WFW_VECTORS_JSON=" + string(raw))
}
