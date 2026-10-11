package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsfullsoftware"
	"testing"
	"time"
)

// Invented data through the real manager store, exported only in fixture logs.
func TestSoftwareHistoryExportInteropVectors(t *testing.T) {
	f := newHistoryFixture(t)
	defer f.s.Close()
	type vector struct {
		Name  string                          `json:"name"`
		Query windowsfullsoftware.Query       `json:"query"`
		Page  windowsfullsoftware.HistoryPage `json:"page"`
	}
	vectors := []vector{}
	q := historyQuery()
	vectors = append(vectors, vector{"awaiting", q, historyPage(t, f)})
	rows := []windowsfullsoftware.Row{softwareRow(1, softwareText("Duplicate 東京"), softwareText("2"), nil, "64"), softwareRow(2, softwareText("Duplicate 東京"), nil, nil, "32")}
	f.capture(t, 1, rows)
	vectors = append(vectors, vector{"baseline", q, historyPage(t, f)})
	f.at = f.at.Add(time.Minute)
	rows[0].Version = softwareText("1")
	f.capture(t, 2, rows[:1])
	vectors = append(vectors, vector{"observedChanges", q, historyPage(t, f)})
	q.Limit = 1
	p, e := f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e != nil {
		t.Fatal(e)
	}
	vectors = append(vectors, vector{"firstPage", q, p})
	q.Cursor = p.NextCursor
	p, e = f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e != nil {
		t.Fatal(e)
	}
	vectors = append(vectors, vector{"continuation", q, p})
	raw, e := json.Marshal(vectors)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("WSH_VECTORS_JSON=" + string(raw))
}
