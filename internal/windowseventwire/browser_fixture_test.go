package windowseventwire

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/windowseventrequest"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This same invented fixture is consumed by the real TypeScript parser suite.
// Validate it in both languages so a future DTO change cannot silently leave a
// stale, independently hand-maintained browser contract looking interoperable.
func TestSharedBrowserFixtureMatchesNativeContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "windows-event-content-go-fixture.json"))
	if err != nil {
		t.Fatal("shared synthetic browser fixture unavailable", err)
	}
	var fixture struct {
		Record RecordDTO `json:"record"`
		Page   struct {
			Identity  windowseventrequest.Identity `json:"identity"`
			Receipt   windowseventrequest.Receipt  `json:"receipt"`
			Report    ReportDTO                    `json:"report"`
			ExpiresAt time.Time                    `json:"expiresAt"`
		} `json:"page"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fixture) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("shared fixture schema drifted")
	}
	record, err := fixture.Record.Native()
	if err != nil || record.State != windowseventrequest.Accepted || record.Receipt == nil {
		t.Fatal("shared fixture lost native accepted authority", err)
	}
	if len(record.Description.Query.Events) != 2 || record.Description.Query.Events[0].RecordID != math.MaxUint64 || record.Description.Query.Events[1].RecordID != 9007199254740993 || record.Description.Identity.Sequence != 9007199254740993 {
		t.Fatal("shared fixture no longer proves full-width identities")
	}
	if fixture.Page.Identity != record.Description.Identity || fixture.Page.Receipt != *record.Receipt || !fixture.Page.ExpiresAt.Equal(record.Description.ExpiresAt) {
		t.Fatal("shared page is not exactly bound to its request and receipt")
	}
	report, err := fixture.Page.Report.Native(record.Description.Query)
	if err != nil {
		t.Fatal("shared report is not a valid native result", err)
	}
	digest, err := ReportDigest(report, record.Description.Query)
	if err != nil || digest != record.Receipt.ResultDigest {
		t.Fatal("shared receipt lost its native report digest", err)
	}
	projected, err := RecordForBrowser(record)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(fixture.Record)
	got, _ := json.Marshal(projected)
	if !bytes.Equal(want, got) {
		t.Fatal("native-to-browser projection changed shared fixture")
	}
}
