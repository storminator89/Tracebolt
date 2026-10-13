package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/macosinventory"
	"localrmm/internal/macosinventorywire"
)

func macInventoryLookupQuery(section, generation, search string) MacOSInventoryQuery {
	return MacOSInventoryQuery{Section: section, GenerationID: generation, Limit: 100, SchemaVersion: MacOSInventoryLookupQueryVersion, Search: &search}
}

func TestMacOSInventoryLookupQueryAndLegacyBytes(t *testing.T) {
	generation := "sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	legacy := MacOSInventoryQuery{Section: "processes", GenerationID: generation, Limit: 100}
	raw, err := json.Marshal(legacy)
	if err != nil || string(raw) != `{"section":"processes","generationId":"sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","offset":0,"limit":100}` {
		t.Fatal("legacy query bytes changed", err)
	}
	p := MacOSInventoryPage{SchemaVersion: "tracebolt.macos-read-inventory-page.v1", Section: "processes", ReceiptIDs: []string{}, Processes: []macosinventory.Process{}, Interfaces: []macosinventory.Interface{}}
	raw, err = json.Marshal(p)
	if err != nil || string(raw) != `{"schemaVersion":"tracebolt.macos-read-inventory-page.v1","deviceId":"","section":"processes","status":"","serverNow":"0001-01-01T00:00:00Z","authorityUntil":"0001-01-01T00:00:00Z","generationId":"","sourceQuality":"","collectedAt":null,"expiresAt":null,"sources":null,"hardware":null,"receiptIds":[],"processes":[],"interfaces":[],"offset":0,"total":0,"nextOffset":null}` {
		t.Fatal("legacy page bytes changed", err)
	}
	if err := ValidateMacOSInventoryQuery(legacy); err != nil {
		t.Fatal("legacy query rejected", err)
	}
	for _, search := range []string{"", "a", "a b", "literal.*[]%_+", `a\"b`, strings.Repeat("z", 256)} {
		q := macInventoryLookupQuery("processes", generation, search)
		if err := ValidateMacOSInventoryQuery(q); err != nil {
			t.Fatal("canonical search rejected", err)
		}
		raw, _ := json.Marshal(q)
		if !bytes.Contains(raw, []byte(`"search":`)) {
			t.Fatal("explicit empty search omitted")
		}
	}
	for _, search := range []string{"A", "Mixed", " a", "a ", " ", "\ta", "a\n", "\x00", "\x1f", "\x7f", "é", strings.Repeat("z", 257)} {
		if err := ValidateMacOSInventoryQuery(macInventoryLookupQuery("processes", generation, search)); !errors.Is(err, macosinventorywire.ErrInvalid) {
			t.Fatal("noncanonical search admitted", err)
		}
	}
	for _, kind := range []string{"legacy-search", "empty-version", "v1-version", "unknown-version", "missing-search", "summary", "hardware", "ipv4", "ipv6", "missing-generation", "wrong-generation", "negative-offset", "offset-limit", "zero-limit", "row-limit"} {
		t.Run(kind, func(t *testing.T) {
			q := macInventoryLookupQuery("processes", generation, "")
			switch kind {
			case "legacy-search", "empty-version":
				q.SchemaVersion = ""
			case "v1-version":
				q.SchemaVersion = "tracebolt.macos-read-inventory-query.v1"
			case "unknown-version":
				q.SchemaVersion += ".unknown"
			case "missing-search":
				q.Search = nil
			case "summary", "hardware", "ipv4", "ipv6":
				q.Section = kind
			case "missing-generation":
				q.GenerationID = ""
			case "wrong-generation":
				q.GenerationID = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "negative-offset":
				q.Offset = -1
			case "offset-limit":
				q.Offset = macosinventory.MaxProcesses + 1
			case "zero-limit":
				q.Limit = 0
			case "row-limit":
				q.Limit = 101
			}
			if err := ValidateMacOSInventoryQuery(q); !errors.Is(err, macosinventorywire.ErrInvalid) {
				t.Fatal("invalid lookup admitted", err)
			}
		})
	}
}

func applyMacInventoryLookupSnapshot(t *testing.T, f macInventoryFixture, mutate func(*macosinventory.Snapshot)) macosinventorywire.Report {
	t.Helper()
	r, err := macosinventorywire.DecodeReport(f.report(t, 1, f.at, 1))
	if err != nil {
		t.Fatal(err)
	}
	mutate(&r.Snapshot)
	r, err = macosinventorywire.BuildReport(f.enable, 1, r.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := macosinventorywire.EncodeReport(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.apply(raw, f.at); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMacOSInventoryLookupLiteralSourceOrderAndCounts(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	r := applyMacInventoryLookupSnapshot(t, f, func(s *macosinventory.Snapshot) {
		s.Receipts.Identifiers = []string{"COM.Example.Alpha", "com.example.Beta", "com.example.alpha+addon", "org.example.Zed"}
		s.Processes.Rows = []macosinventory.Process{
			{PID: 0, ParentPID: 0, AccountingName: "Kernel", NameQuality: "observed"},
			{PID: 7, ParentPID: 12, AccountingName: "Alpha Agent", NameQuality: "observed"},
			{PID: 12, ParentPID: 34, AccountingName: "Literal.*[x]", NameQuality: "observed"},
			{PID: 34, ParentPID: 7, AccountingName: "Beta Agent", NameQuality: "observed"},
			{PID: 112, ParentPID: 0, AccountingName: "", NameQuality: "unavailable"},
			{PID: 2147483647, ParentPID: 2147483647, AccountingName: "Maximum", NameQuality: "observed"},
		}
	})
	for _, tc := range []struct {
		search string
		pids   []uint32
	}{
		{"", []uint32{0, 7, 12, 34, 112, 2147483647}},
		{"agent", []uint32{7, 34}}, {"12", []uint32{7, 12, 112}},
		{"0", []uint32{0, 112}}, {"2147483647", []uint32{2147483647}},
		{"*", []uint32{12}}, {"[x]", []uint32{12}}, {".*", []uint32{12}},
		{"1234", nil}, {"12 34", nil}, {"agent12", nil}, {"unavailable", nil},
		{"unknown", nil}, {"not present", nil}, {"2147483648", nil},
	} {
		p, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, macInventoryLookupQuery("processes", r.GenerationID, tc.search), f.at)
		if err != nil {
			t.Fatal(err)
		}
		var pids []uint32
		for _, row := range p.Processes {
			pids = append(pids, row.PID)
		}
		if !reflect.DeepEqual(pids, tc.pids) || p.Total != 6 || p.MatchingCount == nil || *p.MatchingCount != len(tc.pids) || p.Search == nil || *p.Search != tc.search || p.SchemaVersion != MacOSInventoryLookupPageVersion || p.NextOffset != nil {
			t.Fatalf("lookup mismatch for %q: got %v", tc.search, pids)
		}
		if p.SourceQuality != "partial" || p.Sources.Processes.Quality != "observed" || !p.CollectedAt.Equal(f.at) || !p.ExpiresAt.Equal(f.at.Add(24*time.Hour)) || !p.AuthorityUntil.Equal(f.at.Add(24*time.Hour)) {
			t.Fatal("lookup changed source truth or original time")
		}
	}
	// A source's unavailable-name value cannot acquire a searchable placeholder.
	if macOSInventoryProcessMatches(macosinventory.Process{PID: 7, ParentPID: 12, AccountingName: "Unavailable", NameQuality: "unavailable"}, "unavailable") {
		t.Fatal("unavailable placeholder matched")
	}
	for _, tc := range []struct {
		search string
		ids    []string
	}{
		{"alpha", []string{"COM.Example.Alpha", "com.example.alpha+addon"}},
		{"+", []string{"com.example.alpha+addon"}},
		{"*", []string{}}, {"%", []string{}}, {"_", []string{}},
	} {
		p, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, macInventoryLookupQuery("receipts", r.GenerationID, tc.search), f.at)
		if err != nil || !reflect.DeepEqual(p.ReceiptIDs, tc.ids) || p.Total != 4 || p.MatchingCount == nil || *p.MatchingCount != len(tc.ids) {
			t.Fatal("receipt lookup/order", tc.search, err)
		}
	}
	// Empty v2 lookup equals the actual legacy page byte-for-byte after removing
	// only its declared version and two new fields, including a zero-row result.
	for _, section := range []string{"processes", "receipts"} {
		q := MacOSInventoryQuery{Section: section, GenerationID: r.GenerationID, Limit: 100}
		legacy, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at)
		if err != nil {
			t.Fatal(err)
		}
		lookup, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, macInventoryLookupQuery(section, r.GenerationID, ""), f.at)
		if err != nil || lookup.MatchingCount == nil || *lookup.MatchingCount != lookup.Total {
			t.Fatal("empty lookup", err)
		}
		lookup.SchemaVersion, lookup.Search, lookup.MatchingCount = legacy.SchemaVersion, nil, nil
		a, _ := json.Marshal(legacy)
		b, _ := json.Marshal(lookup)
		if !bytes.Equal(a, b) {
			t.Fatal("legacy page changed by empty lookup")
		}
	}
}

func TestMacOSInventoryLookupFilteredPaginationAndBounds(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	r := applyMacInventoryLookupSnapshot(t, f, func(s *macosinventory.Snapshot) {
		s.Processes.Rows = make([]macosinventory.Process, macosinventory.MaxProcesses)
		for i := range s.Processes.Rows {
			name := "Other"
			if i >= 101 && i%2 == 1 {
				name = "Target"
			}
			s.Processes.Rows[i] = macosinventory.Process{PID: uint32(i + 1), ParentPID: 0, AccountingName: name, NameQuality: "observed"}
		}
		s.Receipts.Identifiers = []string{}
		for i := 0; i < 200; i++ {
			s.Receipts.Identifiers = append(s.Receipts.Identifiers, fmt.Sprintf("com.fixture.%03d.%s", i, strings.Repeat("a", 240)))
		}
	})
	q := macInventoryLookupQuery("processes", r.GenerationID, "target")
	seen := 0
	for {
		p, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(p)
		if p.Total != macosinventory.MaxProcesses || p.MatchingCount == nil || *p.MatchingCount != 1998 || len(p.Processes) == 0 || len(p.Processes) > 100 || len(raw) > MacOSInventoryMaxPageBytes || p.Offset != seen {
			t.Fatal("page count/bounds", p.Total, p.MatchingCount, len(raw))
		}
		for _, row := range p.Processes {
			if row.PID != uint32(102+2*seen) {
				t.Fatal("filtered source order/offset", row.PID, seen)
			}
			seen++
		}
		if p.NextOffset == nil {
			break
		}
		if *p.NextOffset != seen {
			t.Fatal("continuation used source offset")
		}
		q.Offset = *p.NextOffset
	}
	if seen != 1998 {
		t.Fatal("lost filtered rows", seen)
	}
	q.Offset = seen
	end, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at)
	if err != nil || len(end.Processes) != 0 || end.NextOffset != nil {
		t.Fatal("matching end offset", err)
	}
	q.Offset++
	if _, err = f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at); !errors.Is(err, macosinventorywire.ErrInvalid) {
		t.Fatal("offset beyond matching count admitted", err)
	}
	q = macInventoryLookupQuery("receipts", r.GenerationID, strings.Repeat("a", 240))
	for _, offset := range []int{0, 100} {
		q.Offset = offset
		p, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at)
		raw, _ := json.Marshal(p)
		if err != nil || p.Total != 200 || p.MatchingCount == nil || *p.MatchingCount != 200 || len(p.ReceiptIDs) != 100 || len(raw) > MacOSInventoryMaxPageBytes {
			t.Fatal("maximum whole receipt rows", err, len(raw))
		}
		for i, row := range p.ReceiptIDs {
			if row != r.Snapshot.Receipts.Identifiers[offset+i] || len(row) != 256 {
				t.Fatal("receipt row truncated/reordered")
			}
		}
	}
}

func TestMacOSInventoryLookupEmptyAndUnavailableStayDistinct(t *testing.T) {
	for _, quality := range []string{"observed", "denied", "unavailable"} {
		t.Run(quality, func(t *testing.T) {
			f := newMacInventoryFixture(t)
			f.grant(t)
			r := applyMacInventoryLookupSnapshot(t, f, func(s *macosinventory.Snapshot) {
				s.Receipts.Identifiers = []string{}
				if quality != "observed" {
					reason := macosinventory.ErrDenied.Error()
					if quality == "unavailable" {
						reason = macosinventory.ErrUnavailable.Error()
					}
					s.Receipts.Quality, s.Receipts.Reason = quality, reason
					s.Processes.Quality, s.Processes.Reason = quality, reason
					s.Processes.Rows = []macosinventory.Process{}
				}
			})
			for _, section := range []string{"receipts", "processes"} {
				for _, search := range []string{"", "no match"} {
					p, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, macInventoryLookupQuery(section, r.GenerationID, search), f.at)
					if err != nil || p.MatchingCount == nil || p.Search == nil || p.Sources == nil || p.Sources.Receipts.Quality != quality || p.Sources.Processes.Quality != quality {
						t.Fatal("source unknown became observed", err)
					}
					wantTotal, wantMatches := 0, 0
					if quality == "observed" && section == "processes" {
						wantTotal = 1
						if search == "" {
							wantMatches = 1
						}
					}
					if p.Total != wantTotal || *p.MatchingCount != wantMatches {
						t.Fatal("unknown/empty count changed")
					}
					raw, _ := json.Marshal(p)
					if !bytes.Contains(raw, []byte(`"matchingCount":`)) || !bytes.Contains(raw, []byte(`"search":`)) {
						t.Fatal("v2 zero or empty fields missing")
					}
				}
			}
		})
	}
}

func TestMacOSInventoryLookupOriginalAndFinalAuthority(t *testing.T) {
	for _, kind := range []string{"replacement", "disable", "revoke", "session-change", "logout", "final-session", "report-expiry", "final-expiry", "leaf-expiry"} {
		t.Run(kind, func(t *testing.T) {
			f := newMacInventoryFixture(t)
			if kind == "leaf-expiry" {
				f.at = time.Unix(f.snap.Intent.NotAfter, 0).UTC().Add(-time.Hour)
				f.enable.ChangedAt = f.at
			}
			f.grant(t)
			r := applyMacInventoryLookupSnapshot(t, f, func(*macosinventory.Snapshot) {})
			q := macInventoryLookupQuery("processes", r.GenerationID, "fixture")
			ctx, at := f.session(), f.at
			p, err := f.s.MacOSInventoryPage(ctx, f.snap.Approval.DeviceID, q, at)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "replacement":
				at = at.Add(time.Minute)
				if _, err = f.apply(f.report(t, 2, at, 1), at); err != nil {
					t.Fatal(err)
				}
			case "disable":
				disable, _ := macosinventorywire.Disable(f.enable, 1, at)
				raw, _ := macosinventorywire.EncodeControl(disable)
				if _, err = f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), raw, at); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				control := f.f.control(f.snap, 50)
				control.Now = at.Unix()
				if _, err = f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
					t.Fatal(err)
				}
			case "session-change":
				ctx = WithMacOSInventorySession(context.Background(), "different-session", at.Add(time.Hour), func() bool { return true })
			case "logout":
				ctx = WithMacOSInventorySession(context.Background(), "fixture-session", at.Add(time.Hour), func() bool { return false })
			case "final-session":
				calls := 0
				ctx = WithMacOSInventorySession(context.Background(), "fixture-session", at.Add(time.Hour), func() bool { calls++; return calls == 1 })
			case "report-expiry":
				at = at.Add(24 * time.Hour)
			case "final-expiry":
				calls := 0
				ctx = WithMacOSInventoryClock(ctx, func() time.Time {
					calls++
					if calls == 1 {
						return at
					}
					return at.Add(24 * time.Hour)
				})
			case "leaf-expiry":
				at = time.Unix(f.snap.Intent.NotAfter, 0).UTC()
				if !p.AuthorityUntil.Equal(at) {
					t.Fatal("lookup not clipped to current leaf")
				}
			}
			if err = f.s.RecheckMacOSInventoryPage(ctx, p, at); err == nil {
				t.Fatal("prepared lookup survived authority change")
			}
			if kind == "session-change" || kind == "final-session" || kind == "final-expiry" {
				return // A new authenticated session can query, but cannot reuse this page.
			}
			if page, err := f.s.MacOSInventoryPage(ctx, f.snap.Approval.DeviceID, q, at); err == nil || page.DeviceID != "" {
				t.Fatal("lookup returned rows after authority change", err)
			}
		})
	}
}

// Invented rows only. The exact Go pages exercise the TypeScript wire validator;
// nothing here reads an OS provider or writes private telemetry to artifacts.
func TestMacOSInventoryLookupExportInteropVectors(t *testing.T) {
	type vector struct {
		Name  string              `json:"name"`
		Query MacOSInventoryQuery `json:"query"`
		Page  MacOSInventoryPage  `json:"page"`
	}
	vectors := []vector{}
	for _, quality := range []string{"observed", "denied"} {
		f := newMacInventoryFixture(t)
		f.grant(t)
		r := applyMacInventoryLookupSnapshot(t, f, func(s *macosinventory.Snapshot) {
			s.Receipts.Identifiers = []string{"COM.Fixture.Alpha", "com.fixture.alpha+addon", "com.fixture.zed"}
			s.Processes.Rows = []macosinventory.Process{
				{PID: 0, ParentPID: 0, AccountingName: "Kernel", NameQuality: "observed"},
				{PID: 101, ParentPID: 12, AccountingName: "Target.*[x]", NameQuality: "observed"},
				{PID: 102, ParentPID: 34, AccountingName: "", NameQuality: "unavailable"},
				{PID: 2147483647, ParentPID: 2147483647, AccountingName: "Target", NameQuality: "observed"},
			}
			if quality == "denied" {
				s.Receipts.Quality, s.Receipts.Reason = "denied", macosinventory.ErrDenied.Error()
				s.Receipts.Identifiers = []string{}
				s.Processes.Quality, s.Processes.Reason = "denied", macosinventory.ErrDenied.Error()
				s.Processes.Rows = []macosinventory.Process{}
			}
		})
		for _, section := range []string{"processes", "receipts"} {
			queries := []MacOSInventoryQuery{{Section: section, GenerationID: r.GenerationID, Limit: 100}, macInventoryLookupQuery(section, r.GenerationID, ""), macInventoryLookupQuery(section, r.GenerationID, "no match")}
			if quality == "observed" {
				searches := []string{"alpha", "+"}
				if section == "processes" {
					searches = []string{"target", "12", "0", "2147483647", "*", "unavailable"}
				}
				for _, search := range searches {
					queries = append(queries, macInventoryLookupQuery(section, r.GenerationID, search))
				}
				first := macInventoryLookupQuery(section, r.GenerationID, searches[0])
				first.Limit = 1
				second := first
				second.Offset = 1
				queries = append(queries, first, second)
			}
			for i, q := range queries {
				p, err := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at)
				if err != nil {
					t.Fatal(err)
				}
				vectors = append(vectors, vector{fmt.Sprintf("%s-%s-%d", quality, section, i), q, p})
			}
		}
		f.s.Close()
	}
	raw, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("MACOS_LOOKUP_VECTORS_JSON=" + string(raw))
}
