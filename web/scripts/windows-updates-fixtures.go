//go:build ignore

// Synthetic source-contract vectors only. No native Windows API is invoked.
// From the repository root, with its pinned Go toolchain:
// go run web/scripts/windows-updates-fixtures.go > /tmp/windows-updates-go-fixture.json
// mv /tmp/windows-updates-go-fixture.json web/src/windows-updates-go-fixture.json
package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"localrmm/internal/windowsupdates"
)

func main() {
	base := windowsupdates.Snapshot{
		SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope,
		GrantID: strings.Repeat("9", 32), GenerationID: "sample_" + strings.Repeat("a", 32),
		CollectedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Source:      "wua-cache", CacheFreshness: "unknown", Quality: "observed", CountExact: true,
		ObservedCount: 1, Rows: []windowsupdates.Update{{UpdateID: "00000001-0000-0000-0000-000000000001", Revision: 2147483647, Title: "Synthetic <update> & Unicode 🛠", KBArticleIDs: []string{"KB1", "KB1234567890"}, Severity: "critical", Downloaded: true, MetadataTruncated: true}},
	}
	type vector struct {
		Name     string          `json:"name"`
		Snapshot json.RawMessage `json:"snapshot"`
	}
	vectors := []vector{}
	add := func(name string, value windowsupdates.Snapshot) {
		encoded, err := windowsupdates.Encode(value)
		if err != nil {
			panic(err)
		}
		vectors = append(vectors, vector{Name: name, Snapshot: encoded})
	}
	add("Go HTML escaping and Unicode metadata", base)
	bounded := base
	bounded.Truncated = true
	bounded.ObservedCount = 2147483647
	add("Exact bounded collection count", bounded)
	bounded.Quality = "partial"
	bounded.Reason = windowsupdates.ErrPartial.Error()
	bounded.CountExact = false
	add("Partial lower-bound count", bounded)
	empty := base
	empty.Rows = []windowsupdates.Update{}
	empty.ObservedCount = 0
	add("Empty cached result, not patch coverage", empty)
	partial := empty
	partial.Quality = "partial"
	partial.Reason = windowsupdates.ErrPartial.Error()
	partial.CountExact = false
	add("Partial empty lower bound", partial)
	denied := empty
	denied.Quality = "denied"
	denied.Reason = windowsupdates.ErrDenied.Error()
	denied.CountExact = false
	add("Access denied", denied)
	unavailable := denied
	unavailable.Quality = "unavailable"
	unavailable.Reason = windowsupdates.ErrOffline.Error()
	add("Offline-only safety check unavailable", unavailable)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(vectors); err != nil {
		panic(err)
	}
}
