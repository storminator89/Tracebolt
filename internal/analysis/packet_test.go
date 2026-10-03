package analysis

import (
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/model"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleCase() (model.Case, []model.Evidence) {
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	e := model.Evidence{ID: "disk-used", Title: "Disk utilization", Source: "synthetic-fixture", Quality: "healthy", CollectedAt: at, Detail: "One synthetic capacity observation, not a hardware-failure diagnosis.", Value: "94.6%", Synthetic: true}
	c := model.Case{ID: "case-storage", Title: "Storage capacity warning", Summary: "A capacity threshold was exceeded; its cause is not established.", Category: "storage", RuleID: "storage.used_gte_90.v1", RunbookID: "storage", EvidenceIDs: []string{e.ID}, Evidence: []model.Evidence{e}, CreatedAt: at, UpdatedAt: at, Synthetic: true}
	return c, []model.Evidence{e}
}

func testPacket(t *testing.T) Packet {
	t.Helper()
	c, e := sampleCase()
	p, err := BuildPacket(c, e)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPacketPreservesEvidenceAndMinimizesContext(t *testing.T) {
	c, e := sampleCase()
	c.DeviceID, c.DeviceName = "private-device-id", "private-device-name"
	c.Notes = []model.Note{{Text: "private-note"}}
	c.Timeline = []model.Activity{{Detail: "private-timeline"}}
	e = append(e, model.Evidence{ID: "unrelated", Detail: "unrelated-secret"})
	p, err := BuildPacket(c, e)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Evidence, c.Evidence) {
		t.Fatalf("evidence changed: %#v", p.Evidence)
	}
	raw, _ := json.Marshal(p)
	for _, absent := range []string{"private-device", "private-note", "private-timeline", "unrelated-secret"} {
		if strings.Contains(string(raw), absent) {
			t.Fatalf("unexpected context %q", absent)
		}
	}
	if p.ObservationWindow.From == nil || !p.ObservationWindow.From.Equal(e[0].CollectedAt) || !p.ObservationWindow.To.Equal(e[0].CollectedAt) {
		t.Fatal("incorrect observation window")
	}
}

func TestPacketDeduplicatesAndPrioritizesDeterministically(t *testing.T) {
	c, e := sampleCase()
	older := e[0]
	older.ID = "older"
	older.CollectedAt = older.CollectedAt.Add(-time.Hour)
	stale := e[0]
	stale.ID = "stale"
	stale.Quality = "stale"
	stale.CollectedAt = stale.CollectedAt.Add(time.Hour)
	c.EvidenceIDs = []string{stale.ID, "missing", older.ID, e[0].ID, e[0].ID}
	e = append(e, stale, older, e[0])
	p, err := BuildPacket(c, e)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, observation := range p.Evidence {
		got = append(got, observation.ID)
	}
	if !reflect.DeepEqual(got, []string{"disk-used", "older", "stale"}) || !reflect.DeepEqual(p.MissingEvidenceIDs, []string{"missing"}) {
		t.Fatalf("incorrect selection: %#v", p)
	}
	if len(p.Gaps) != 2 || p.Gaps[0].Code != "missing-evidence" || p.Gaps[1].Code != "quality-stale" {
		t.Fatalf("missing gaps: %#v", p.Gaps)
	}
	e[0], e[2] = e[2], e[0]
	c.EvidenceIDs = []string{"disk-used", "older", "missing", "stale"}
	other, err := BuildPacket(c, e)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.encode()
	b, _ := other.encode()
	if string(a) != string(b) {
		t.Fatal("packet changes when source/reference order changes")
	}
}

func TestPacketNormalizesTimeWithoutChangingInstant(t *testing.T) {
	c, e := sampleCase()
	e[0].CollectedAt = e[0].CollectedAt.In(time.FixedZone("test-zone", 7200))
	p, err := BuildPacket(c, e)
	if err != nil {
		t.Fatal(err)
	}
	if p.Evidence[0].CollectedAt.Location() != time.UTC || !p.Evidence[0].CollectedAt.Equal(e[0].CollectedAt) {
		t.Fatal("timestamp normalization changed the observation instant")
	}
}

func TestPacketRejectsInvalidOrOversizedInput(t *testing.T) {
	cases := map[string]func(*model.Case, *[]model.Evidence){
		"case ID":      func(c *model.Case, e *[]model.Evidence) { c.ID = "bad\nID" },
		"case summary": func(c *model.Case, e *[]model.Evidence) { c.Summary = strings.Repeat("x", MaxFieldBytes+1) },
		"UTF-8":        func(c *model.Case, e *[]model.Evidence) { (*e)[0].Detail = string([]byte{0xff}) },
		"source":       func(c *model.Case, e *[]model.Evidence) { (*e)[0].Source = "" },
		"quality":      func(c *model.Case, e *[]model.Evidence) { (*e)[0].Quality = "perfect" },
		"timestamp":    func(c *model.Case, e *[]model.Evidence) { (*e)[0].CollectedAt = time.Time{} },
		"ambiguous ID": func(c *model.Case, e *[]model.Evidence) {
			duplicate := (*e)[0]
			duplicate.Value = "different"
			*e = append(*e, duplicate)
		},
		"reference count": func(c *model.Case, e *[]model.Evidence) { c.EvidenceIDs = make([]string, MaxEvidence+1) },
		"source count":    func(c *model.Case, e *[]model.Evidence) { *e = make([]model.Evidence, MaxSourceEvidence+1) },
		"field bytes":     func(c *model.Case, e *[]model.Evidence) { (*e)[0].Value = strings.Repeat("ä", MaxFieldBytes) },
		"serialized bytes": func(c *model.Case, e *[]model.Evidence) {
			for i := 0; i < 10; i++ {
				observation := (*e)[0]
				observation.ID = fmt.Sprintf("large-%d", i)
				observation.Detail = strings.Repeat("x", MaxFieldBytes)
				observation.Value = observation.Detail
				*e = append(*e, observation)
				c.EvidenceIDs = append(c.EvidenceIDs, observation.ID)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c, e := sampleCase()
			mutate(&c, &e)
			if _, err := BuildPacket(c, e); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestPacketMakesAbsentAndUnavailableDataExplicit(t *testing.T) {
	c, e := sampleCase()
	e[0].Quality = "denied"
	e[0].CollectedAt = time.Time{}
	p, err := BuildPacket(c, e)
	if err != nil || p.ObservationWindow.From != nil || len(p.Gaps) != 1 || p.Gaps[0].Code != "quality-denied" {
		t.Fatalf("unavailable timestamp was hidden: %#v %v", p, err)
	}
	p, err = BuildPacket(c, nil)
	if err != nil || p.Evidence == nil || len(p.Evidence) != 0 || len(p.MissingEvidenceIDs) != 1 || len(p.Gaps) != 2 {
		t.Fatalf("missing evidence was hidden: %#v %v", p, err)
	}
}
