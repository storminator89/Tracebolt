package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/macosinventorywire"
)

const macInventoryLookupBody = `{"schemaVersion":"tracebolt.macos-read-inventory-query.v2","section":"processes","generationId":"sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","offset":0,"limit":100,"search":"fixture"}`

type fixtureMacInventoryLookupSource struct {
	fixtureMacInventorySource
	query enrollmentstore.MacOSInventoryQuery
}

func (f *fixtureMacInventoryLookupSource) MacOSInventoryPage(ctx context.Context, device string, q enrollmentstore.MacOSInventoryQuery, at time.Time) (enrollmentstore.MacOSInventoryPage, error) {
	f.query = q
	return f.fixtureMacInventorySource.MacOSInventoryPage(ctx, device, q, at)
}

func TestMacOSInventoryLookupExactRequestShapeAndBounds(t *testing.T) {
	for _, kind := range []string{"legacy", "v2", "empty-search", "receipts", "max-search", "exact-byte-limit", "unknown", "duplicate", "duplicate-version", "null", "null-version", "null-offset", "missing-search", "missing-version", "missing-generation", "v1-version", "unknown-version", "empty-version", "wrong-type", "wrong-search-type", "case", "uppercase-search", "outer-space", "control", "unicode", "long-search", "summary", "hardware", "ipv4", "ipv6", "huge", "trailing-document", "array", "bad-offset", "bad-limit", "mixed-legacy"} {
		t.Run(kind, func(t *testing.T) {
			body := macInventoryLookupBody
			want := http.StatusBadRequest
			switch kind {
			case "legacy":
				body, want = macInventoryQueryBody, http.StatusOK
			case "v2":
				want = http.StatusOK
			case "empty-search":
				body, want = strings.Replace(body, `"fixture"`, `""`, 1), http.StatusOK
			case "receipts":
				body, want = strings.Replace(body, `"processes"`, `"receipts"`, 1), http.StatusOK
			case "max-search":
				body, want = strings.Replace(body, "fixture", strings.Repeat("a", 256), 1), http.StatusOK
			case "exact-byte-limit":
				body += strings.Repeat(" ", 1024-len(body))
				want = http.StatusOK
			case "unknown":
				body = strings.Replace(body, "{", `{"extra":1,`, 1)
			case "duplicate":
				body = strings.Replace(body, "{", `{"search":"fixture",`, 1)
			case "duplicate-version":
				body = strings.Replace(body, "{", `{"schemaVersion":"tracebolt.macos-read-inventory-query.v2",`, 1)
			case "null":
				body = strings.Replace(body, `"fixture"`, `null`, 1)
			case "null-version":
				body = strings.Replace(body, `"tracebolt.macos-read-inventory-query.v2"`, `null`, 1)
			case "null-offset":
				body = strings.Replace(body, `"offset":0`, `"offset":null`, 1)
			case "missing-search":
				body = strings.Replace(body, `,"search":"fixture"`, "", 1)
			case "missing-version":
				body = strings.Replace(body, `"schemaVersion":"tracebolt.macos-read-inventory-query.v2",`, "", 1)
			case "missing-generation":
				body = strings.Replace(body, `"generationId":"sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",`, "", 1)
			case "v1-version":
				body = strings.Replace(body, "query.v2", "query.v1", 1)
			case "unknown-version":
				body = strings.Replace(body, "query.v2", "query.v3", 1)
			case "empty-version":
				body = strings.Replace(body, "tracebolt.macos-read-inventory-query.v2", "", 1)
			case "wrong-type":
				body = strings.Replace(body, `"tracebolt.macos-read-inventory-query.v2"`, `2`, 1)
			case "wrong-search-type":
				body = strings.Replace(body, `"fixture"`, `false`, 1)
			case "case":
				body = strings.Replace(body, "search", "Search", 1)
			case "uppercase-search":
				body = strings.Replace(body, "fixture", "Fixture", 1)
			case "outer-space":
				body = strings.Replace(body, "fixture", " fixture", 1)
			case "control":
				body = strings.Replace(body, "fixture", `\n`, 1)
			case "unicode":
				body = strings.Replace(body, "fixture", "é", 1)
			case "long-search":
				body = strings.Replace(body, "fixture", strings.Repeat("a", 257), 1)
			case "summary", "hardware", "ipv4", "ipv6":
				body = strings.Replace(body, "processes", kind, 1)
			case "huge":
				body += strings.Repeat(" ", 1025-len(body))
				want = http.StatusRequestEntityTooLarge
			case "trailing-document":
				body += "{}"
			case "array":
				body = "[]"
			case "bad-offset":
				body = strings.Replace(body, `"offset":0`, `"offset":4097`, 1)
			case "bad-limit":
				body = strings.Replace(body, `"limit":100`, `"limit":101`, 1)
			case "mixed-legacy":
				body = strings.Replace(macInventoryQueryBody, "{", `{"search":"",`, 1)
			}
			live := true
			f := &fixtureMacInventoryLookupSource{}
			w := httptest.NewRecorder()
			h := operatorHandler{app: &Server{}}
			h.writeMacOSInventoryQuery(w, macInventoryRequest(body, &live), f)
			if w.Code != want {
				t.Fatal("query status", w.Code, want)
			}
			if want != http.StatusOK {
				if f.readCalls != 0 || f.finalCalls != 0 {
					t.Fatal("invalid shape reached source")
				}
				return
			}
			if f.readCalls != 1 || f.finalCalls != 1 {
				t.Fatal("valid lookup missing final guard")
			}
			if kind == "legacy" {
				if f.query.SchemaVersion != "" || f.query.Search != nil {
					t.Fatal("legacy shape promoted")
				}
			} else if f.query.SchemaVersion != enrollmentstore.MacOSInventoryLookupQueryVersion || f.query.Search == nil {
				t.Fatal("lookup version/search missing")
			}
		})
	}
}

func TestMacOSInventoryLookupFinalOutputGuards(t *testing.T) {
	for _, kind := range []string{"success", "expired", "revoked", "disabled", "generation", "logout-during-read", "logout-at-write", "oversize", "source-error"} {
		t.Run(kind, func(t *testing.T) {
			live := true
			search, count := "fixture", 1
			f := &fixtureMacInventoryLookupSource{fixtureMacInventorySource: fixtureMacInventorySource{at: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC), page: enrollmentstore.MacOSInventoryPage{SchemaVersion: enrollmentstore.MacOSInventoryLookupPageVersion, DeviceID: macInventoryDevice, Section: "receipts", ReceiptIDs: []string{"private-synthetic-receipt"}, Total: 2, Search: &search, MatchingCount: &count}}}
			switch kind {
			case "expired":
				f.finalErr = macosinventorywire.ErrExpired
			case "revoked":
				f.finalErr = enrollmentstate.ErrProof
			case "disabled":
				f.finalErr = macosinventorywire.ErrDisabled
			case "generation":
				f.finalErr = macosinventorywire.ErrConflict
			case "logout-during-read":
				f.onRead = func() { live = false }
			case "logout-at-write":
				f.onFinal = func() { live = false }
			case "oversize":
				f.page.ReceiptIDs = []string{strings.Repeat("x", enrollmentstore.MacOSInventoryMaxPageBytes)}
			case "source-error":
				f.readErr = errors.New("private-source-error")
			}
			w := httptest.NewRecorder()
			h := operatorHandler{app: &Server{}}
			h.writeMacOSInventoryQuery(w, macInventoryRequest(strings.Replace(macInventoryLookupBody, "processes", "receipts", 1), &live), f)
			if kind == "success" {
				want, err := json.Marshal(f.page)
				if err != nil || w.Code != 200 || f.finalCalls != 1 || w.Body.String() != string(want) {
					t.Fatal("v2 response changed during output", err, w.Code)
				}
				return
			}
			if w.Code == 200 || strings.Contains(w.Body.String(), "private-synthetic-receipt") || strings.Contains(w.Body.String(), "private-source-error") || strings.Contains(w.Body.String(), `"matchingCount"`) {
				t.Fatal("private lookup escaped final guard", w.Code)
			}
			if kind == "oversize" && f.finalCalls != 0 {
				t.Fatal("oversized response reached final admission")
			}
		})
	}
}
