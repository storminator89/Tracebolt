package windowsfullsoftware

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func historyManifest(t *testing.T, c Consent, seq uint64, rows []Row, at time.Time) Manifest {
	t.Helper()
	m, e := Build(testDevice, c, seq, Capture{StartedAt: at, FinishedAt: at.Add(time.Second), Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	return *m[0].Manifest
}
func TestHistoryLegacyConsentBytesAndScopeBinding(t *testing.T) {
	c := testConsent()
	raw, e := EncodeConsent(c)
	if e != nil || bytes.Contains(raw, []byte("history")) {
		t.Fatal("legacy bytes changed", e)
	}
	c.HistoryScope = HistoryScope
	raw, e = EncodeConsent(c)
	if e != nil {
		t.Fatal(e)
	}
	d, e := DecodeConsent(raw)
	if e != nil || d != c {
		t.Fatal("history grant not exact", e)
	}
	c.HistoryScope = "other"
	if ValidateConsent(c) == nil {
		t.Fatal("unknown history scope")
	}
}
func TestHistoryExactIDsObservedFieldsAndOriginalExpiry(t *testing.T) {
	c := testConsent()
	c.HistoryScope = HistoryScope
	old := testRows(3)
	newRows := testRows(3)
	newRows[0].Version = nil
	newRows[0].VersionQuality = "unavailable"
	v := "0.9"
	newRows[1].Version = &v
	newRows[2].RegistrationID = strings.Repeat("f", 64)
	before := historyManifest(t, c, 1, old, c.ChangedAt)
	after := historyManifest(t, c, 2, newRows, c.ChangedAt.Add(time.Minute))
	changes, n, e := DiffHistory(before, after, old, newRows)
	if e != nil || n != 3 || len(changes) != 3 {
		t.Fatal("observed transitions", n, e)
	}
	kinds := map[string]int{}
	for _, change := range changes {
		kinds[change.Kind]++
		if !change.ExpiresAt.Equal(before.CaptureStartedAt.Add(HistoryRetention)) || !change.BeforeObservedAt.Equal(before.CaptureFinishedAt) || !change.AfterObservedAt.Equal(after.CaptureFinishedAt) {
			t.Fatal("original age lost")
		}
	}
	if kinds["metadata_changed"] != 1 || kinds["registration_added"] != 1 || kinds["registration_removed"] != 1 {
		t.Fatal(kinds)
	}
	for _, alter := range []func(*Manifest){func(m *Manifest) { m.GrantRevision++ }, func(m *Manifest) { m.SenderBinding = strings.Repeat("f", 64) }, func(m *Manifest) { m.Sequence++ }, func(m *Manifest) { m.Source = "guess" }} {
		bad := after
		alter(&bad)
		if _, _, e = DiffHistory(before, bad, old, newRows); e == nil {
			t.Fatal("incomparable accepted")
		}
	}
}
func TestHistoryUnknownNeverBecomesVersionChangeAndWholeDiffBudget(t *testing.T) {
	c := testConsent()
	a := testRows(1)
	b := testRows(1)
	a[0].Version = nil
	a[0].VersionQuality = "unavailable"
	before := historyManifest(t, c, 1, a, c.ChangedAt)
	after := historyManifest(t, c, 2, b, c.ChangedAt.Add(time.Minute))
	changes, n, e := DiffHistory(before, after, a, b)
	if e != nil || n != 0 || len(changes) != 0 {
		t.Fatal("unknown inferred", e)
	}
	a = []Row{}
	b = testRows(MaxHistoryRows + 1)
	before = historyManifest(t, c, 1, a, c.ChangedAt)
	after = historyManifest(t, c, 2, b, c.ChangedAt.Add(time.Minute))
	changes, n, e = DiffHistory(before, after, a, b)
	if !errors.Is(e, ErrBudget) || n != MaxHistoryRows+1 || changes != nil {
		t.Fatal("hidden truncated prefix", n, e)
	}
}
func TestHistoryAdditionalConsentFitsUnchangedSoftwareFrames(t *testing.T) {
	c := testConsent()
	c.HistoryScope = HistoryScope
	rows := testRows(128)
	large := strings.Repeat("<", MaxFieldUTF16)
	for i := range rows {
		rows[i].Name = &large
		rows[i].Version = &large
		rows[i].Publisher = &large
	}
	messages, e := Build(testDevice, c, MaxSequence, Capture{StartedAt: c.ChangedAt, FinishedAt: c.ChangedAt, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	total := 0
	max := 0
	for _, m := range messages {
		raw, e := EncodeMessage(m)
		if e != nil || len(raw) > MaxChunkBytes {
			t.Fatal("frame bound", e)
		}
		if len(raw) > max {
			max = len(raw)
		}
		total += len(raw)
		if decoded, e := DecodeMessage(raw); e != nil || decoded.Consent != c {
			t.Fatal("wire grant lost", e)
		}
	}
	pack, _ := json.Marshal(messages)
	if len(pack) > MaxPackBytes {
		t.Fatal("pack bound")
	}
	t.Logf("history-authorized escaped-maximum-text fixture: %d chunks; max frame=%d <=%d; exact messages=%d; packed=%d <=%d", len(messages), max, MaxChunkBytes, total, len(pack), MaxPackBytes)
}
