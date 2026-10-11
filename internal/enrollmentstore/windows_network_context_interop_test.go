package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsnetworkcontext"
	"testing"
)

// Invented native-source values only, exported from actual durable typed pages.
func TestWindowsNetworkContextExportInteropVectors(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	type vector struct {
		Name  string                      `json:"name"`
		Query windowsnetworkcontext.Query `json:"query"`
		Page  windowsnetworkcontext.Page  `json:"page"`
	}
	vectors := []vector{}
	_, cold, _, coldSnap, _ := activeWindowsStore(t, "tls")
	defer cold.Close()
	coldQuery := networkContextQuery()
	coldQuery.Kind = "route"
	coldPage, e := cold.WindowsNetworkContextPage(context.Background(), coldSnap.Approval.DeviceID, coldQuery, f.at)
	if e != nil || coldPage.Kind != "route" || coldPage.Status != "not_configured" {
		t.Fatal("cold context schema", e)
	}
	vectors = append(vectors, vector{"schemaAbsent", coldQuery, coldPage})

	q := networkContextQuery()
	q.Kind = "route"
	at := f.at
	failure := windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 1, AttemptedAt: &at, Reason: "access_denied"}
	if _, e := f.apply(t, failure, at); e != nil {
		t.Fatal(e)
	}
	vectors = append(vectors, vector{"unavailable", q, f.page(t, q, at)})
	for _, m := range f.messages(t, 2, 257, at) {
		if _, e := f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
	page := f.page(t, q, at)
	vectors = append(vectors, vector{"first257", q, page})
	q.Cursor = page.NextCursor
	page = f.page(t, q, at)
	vectors = append(vectors, vector{"second100", q, page})
	q.Cursor = ""
	q.Search = "::256/"
	vectors = append(vectors, vector{"lateSearch", q, f.page(t, q, at)})
	q.Search = ""
	failure.Sequence = 3
	if _, e := f.apply(t, failure, at); e != nil {
		t.Fatal(e)
	}
	vectors = append(vectors, vector{"retainedLatestFailed", q, f.page(t, q, at)})
	alias := "Synthetic 東京 interface"
	rows := []windowsnetworkcontext.Row{
		{ID: 1, Kind: "route", InterfaceIndex: 7, Route: &windowsnetworkcontext.Route{Destination: "fe80::/64", DestinationScopeID: 7, NextHop: "fe80::1%7", Metric: 4294967295, Protocol: 2, Origin: 3}},
		{ID: 2, Kind: "route", InterfaceIndex: 7, Route: &windowsnetworkcontext.Route{Destination: "0.0.0.0/0", NextHop: "192.0.2.1", Metric: 15, Protocol: 10006}},
		{ID: 3, Kind: "interface", InterfaceIndex: 7, Counters: &windowsnetworkcontext.Counters{Alias: &alias, AliasQuality: "observed", InOctets: "18446744073709551615", OutOctets: "9007199254740993", InErrors: "0", OutErrors: "4294967296", InDiscards: "2", OutDiscards: "3"}},
		{ID: 4, Kind: "interface", InterfaceIndex: 12, Counters: &windowsnetworkcontext.Counters{AliasQuality: "unavailable", InOctets: "0", OutOctets: "0", InErrors: "0", OutErrors: "0", InDiscards: "0", OutDiscards: "0"}},
	}
	capture := func(sequence uint64, rows []windowsnetworkcontext.Row) {
		ms, e := windowsnetworkcontext.Build(f.snap.Approval.DeviceID, f.consent, sequence, windowsnetworkcontext.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: rows})
		if e != nil {
			t.Fatal(e)
		}
		for _, m := range ms {
			if _, e = f.apply(t, m, at); e != nil {
				t.Fatal(e)
			}
		}
	}
	capture(4, rows)
	vectors = append(vectors, vector{"scopedRoutes", q, f.page(t, q, at)})
	q.Kind = "interface"
	vectors = append(vectors, vector{"exactCounters", q, f.page(t, q, at)})
	q.Kind = "all"
	q.Sort = "interface-desc"
	vectors = append(vectors, vector{"allByInterface", q, f.page(t, q, at)})
	capture(5, []windowsnetworkcontext.Row{})
	vectors = append(vectors, vector{"completeEmpty", q, f.page(t, q, at)})
	raw, e := json.Marshal(vectors)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("WNC_VECTORS_JSON=" + string(raw))
}
