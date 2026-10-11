package enrollmentstore

import (
	"encoding/json"
	"localrmm/internal/windowsusersoftware"
	"strings"
	"testing"
	"time"
)

// Export only invented data through a portable fixture log. No runtime export
// path, credentials, native source or production storage is exposed.
func TestWindowsUserSoftwareExportInteropVectors(t *testing.T) {
	f := newUserSoftwareFixture(t, "tls")
	defer f.s.Close()
	type vector struct {
		Name  string                    `json:"name"`
		Query windowsusersoftware.Query `json:"query"`
		Page  windowsusersoftware.Page  `json:"page"`
	}
	q := windowsusersoftware.Query{Sort: "name-asc", Limit: 2}
	vectors := []vector{{"notConfigured", q, f.page(t, q, f.at)}}
	f.grant(t)
	rows := f.messages(t, 1, 3, f.at)[0].Rows
	rows[1].Source = "msix"
	cp := windowsusersoftware.Capture{AccountContextID: strings.Repeat("d", 64), AccountLabel: "Selected account dddddddd", CaptureNonce: strings.Repeat("e", 64), HKCUStatus: "complete", MSIXStatus: "complete", StartedAt: f.at, FinishedAt: f.at, Rows: rows, Complete: true}
	messages, e := windowsusersoftware.Build(f.snap.Approval.DeviceID, f.consent, 1, cp)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	p := f.page(t, q, f.at)
	if len(p.Rows) != 2 || p.NextCursor == "" {
		t.Fatal("fixture paging")
	}
	vectors = append(vectors, vector{"completeFirst", q, p})
	q.AccountContextID = cp.AccountContextID
	q.Cursor = p.NextCursor
	p = f.page(t, q, f.at)
	if p.Offset != 2 || len(p.Rows) != 1 {
		t.Fatal("fixture continuation")
	}
	vectors = append(vectors, vector{"completeContinuation", q, p})
	q.Cursor = ""
	q.Source = "msix"
	p = f.page(t, q, f.at)
	if p.MatchingCount != 1 || p.Rows[0].Source != "msix" {
		t.Fatal("fixture source filter")
	}
	vectors = append(vectors, vector{"msixOnly", q, p})
	at := f.at.Add(time.Minute)
	for _, m := range f.messages(t, 2, 1, at) {
		if _, e = f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
	q = windowsusersoftware.Query{Sort: "name-asc", Limit: 2}
	vectors = append(vectors, vector{"partialHKCU", q, f.page(t, q, at)})
	at = at.Add(time.Minute)
	cp.StartedAt = at
	cp.FinishedAt = at
	cp.Rows = []windowsusersoftware.Row{}
	cp.HKCUStatus = "access_denied"
	cp.MSIXStatus = "unsupported"
	cp.CaptureNonce = strings.Repeat("f", 64)
	messages, e = windowsusersoftware.Build(f.snap.Approval.DeviceID, f.consent, 3, cp)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
	vectors = append(vectors, vector{"bothUnavailable", q, f.page(t, q, at)})
	raw, e := json.Marshal(vectors)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("WUS_VECTORS_JSON=" + string(raw))
}
