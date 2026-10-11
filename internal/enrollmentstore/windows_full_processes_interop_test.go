package enrollmentstore

import (
	"encoding/json"
	"localrmm/internal/windowsfullprocesses"
	"testing"
)

// Invented data only: durable typed pages exported for the UI contract checks.
func TestWindowsFullProcessesExportInteropVectors(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	type vector struct {
		Name  string                     `json:"name"`
		Query windowsfullprocesses.Query `json:"query"`
		Page  windowsfullprocesses.Page  `json:"page"`
	}
	vectors := []vector{}
	q := windowsfullprocesses.Query{Sort: "pid-asc", Limit: 100}
	at := f.at
	failure := windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 1, AttemptedAt: &at, Reason: "access_denied"}
	if _, e := f.apply(t, failure, f.at); e != nil {
		t.Fatal(e)
	}
	vectors = append(vectors, vector{"unavailable", q, f.page(t, q, f.at)})
	for _, m := range f.messages(t, 2, 2051, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	p := f.page(t, q, f.at)
	if len(p.Rows) != 100 || p.Rows[0].PID != 0 || p.Complete.Manifest.RowCount != 2051 {
		t.Fatal("missing PID zero or complete count")
	}
	vectors = append(vectors, vector{"first2051", q, p})
	for i := 0; i < 7; i++ {
		q.Cursor = p.NextCursor
		p = f.page(t, q, f.at)
		if i == 0 {
			vectors = append(vectors, vector{"second100", q, p})
		}
	}
	if p.Offset != 700 || p.Rows[0].PID != 700 {
		t.Fatal("late offset")
	}
	vectors = append(vectors, vector{"offset700", q, p})
	q.Cursor = ""
	q.Search = "02049"
	p = f.page(t, q, f.at)
	if p.MatchingCount != 1 || p.Rows[0].PID != 2049 {
		t.Fatal("late search")
	}
	vectors = append(vectors, vector{"search2049", q, p})
	failure.Sequence = 3
	if _, e := f.apply(t, failure, f.at); e != nil {
		t.Fatal(e)
	}
	q.Search = ""
	vectors = append(vectors, vector{"priorCompleteLatestFailed", q, f.page(t, q, f.at)})
	f.capture(t, 4, []windowsfullprocesses.Row{processRow(0, 0, 0, nil), processRow(2, 0, 1, processText("Same 東京")), processRow(10, 2, 3, processText("Same 東京"))})
	vectors = append(vectors, vector{"duplicateNamesUnavailableZero", q, f.page(t, q, f.at)})
	f.capture(t, 5, []windowsfullprocesses.Row{})
	vectors = append(vectors, vector{"completeZero", q, f.page(t, q, f.at)})
	raw, e := json.Marshal(vectors)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("WFP_VECTORS_JSON=" + string(raw))
}
