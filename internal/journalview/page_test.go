package journalview

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPagesPreservePinnedSnapshotAndExactOrdering(t *testing.T) {
	q, now := fixtureQuery()
	var input strings.Builder
	for i := 0; i < MaxRows; i++ {
		input.WriteString(fixtureLine(q, fmt.Sprintf("fixture row %03d", i)))
	}
	s := mustParse(t, q, now, strings.NewReader(input.String()))
	digest, e := SnapshotDigest(s)
	if e != nil {
		t.Fatal(e)
	}
	var got []Row
	offset, pages := 0, 0
	for {
		p, e := SelectPage(s, digest, offset, MaxPageRows)
		if e != nil {
			t.Fatal(e)
		}
		pages++
		if p.SnapshotDigest != digest || p.Query != q || p.ObservedAt != now || p.TotalCapturedRows != MaxRows || len(p.Rows) > MaxPageRows || p.Offset != offset || p.RedactionWarning != RedactionWarning {
			t.Fatal("page metadata changed")
		}
		encoded, e := EncodePage(p)
		if e != nil || len(encoded) > MaxPageBytes {
			t.Fatal(e)
		}
		again, e := SelectPage(s, digest, offset, MaxPageRows)
		if e != nil {
			t.Fatal(e)
		}
		encodedAgain, _ := EncodePage(again)
		if !bytes.Equal(encoded, encodedAgain) {
			t.Fatal("page changed")
		}
		got = append(got, p.Rows...)
		if p.NextOffset == nil {
			break
		}
		if *p.NextOffset <= offset {
			t.Fatal("no progress")
		}
		offset = *p.NextOffset
	}
	if pages != 5 || !reflect.DeepEqual(got, s.Rows) {
		t.Fatal("missing/duplicated/reordered rows", pages, len(got))
	}
	// The page slice owns its own storage, so local page edits do not mutate the
	// source snapshot or a later page with the original pinned digest.
	p, _ := SelectPage(s, digest, 0, 1)
	p.Rows[0].Message = "changed page fixture"
	same, e := SnapshotDigest(s)
	if e != nil || same != digest {
		t.Fatal("aliased snapshot")
	}
}
func TestByteBoundPagesContinueWithoutDroppingRows(t *testing.T) {
	q, now := fixtureQuery()
	s := mustParse(t, q, now, strings.NewReader(strings.Repeat(fixtureLine(q, strings.Repeat("<", MaxMessageBytes)), MaxRows)))
	if s.Reason != ReasonByteLimit {
		t.Fatal("fixture must be partial")
	}
	digest, _ := SnapshotDigest(s)
	offset, total := 0, 0
	for {
		p, e := SelectPage(s, digest, offset, MaxPageRows)
		if e != nil {
			t.Fatal(e)
		}
		b, e := EncodePage(p)
		if e != nil || len(b) > MaxPageBytes || len(p.Rows) == 0 || len(p.Rows) >= MaxPageRows || p.Coverage != Partial || p.Reason != ReasonByteLimit || p.CountExact || p.ObservedCount != s.ObservedCount || p.TotalCapturedRows != len(s.Rows) {
			t.Fatal("byte-limited page", e)
		}
		total += len(p.Rows)
		if p.NextOffset == nil {
			break
		}
		offset = *p.NextOffset
	}
	if total != len(s.Rows) {
		t.Fatal("missing rows")
	}
}
func TestPageConflictAndEmptySnapshots(t *testing.T) {
	q, now := fixtureQuery()
	s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, "first")))
	digest, _ := SnapshotDigest(s)
	for _, offset := range []int{-1, 1, 2} {
		if _, e := SelectPage(s, digest, offset, 1); e != ErrPageConflict {
			t.Fatal("offset", offset, e)
		}
	}
	if _, e := SelectPage(s, "sha256:"+strings.Repeat("0", 64), 0, 1); e != ErrPageConflict {
		t.Fatal("wrong digest", e)
	}
	changed := s
	changed.Rows = append([]Row(nil), s.Rows...)
	changed.Rows[0].Message = "changed snapshot fixture"
	if _, e := SelectPage(changed, digest, 0, 1); e != ErrPageConflict {
		t.Fatal("changed snapshot", e)
	}
	changed = s
	changed.ObservedAt = now.Add(1)
	if _, e := SelectPage(changed, digest, 0, 1); e != ErrPageConflict {
		t.Fatal("changed time", e)
	}
	for _, limit := range []int{-1, 0, MaxPageRows + 1} {
		if _, e := SelectPage(s, digest, 0, limit); e != ErrInvalidInput {
			t.Fatal("limit", e)
		}
	}
	for _, emptySnapshot := range []Snapshot{empty(q, now), mark(empty(q, now), ReasonPermissionDenied), mark(empty(q, now), ReasonVisibilityRestricted)} {
		d, _ := SnapshotDigest(emptySnapshot)
		p, e := SelectPage(emptySnapshot, d, 0, 1)
		if e != nil || len(p.Rows) != 0 || p.NextOffset != nil || p.TotalCapturedRows != 0 || p.Coverage != emptySnapshot.Coverage {
			t.Fatal("empty", e)
		}
		if _, e := EncodePage(p); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPageValidationAndDiagnosticRedaction(t *testing.T) {
	q, now := fixtureQuery()
	s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, "sensitive page fixture")))
	d, _ := SnapshotDigest(s)
	p, _ := SelectPage(s, d, 0, 1)
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, p), "sensitive page fixture") {
			t.Fatal("diagnostic leak")
		}
	}
	p.NextOffset = new(int)
	if _, e := EncodePage(p); e != ErrInvalidSnapshot {
		t.Fatal("unexpected continuation", e)
	}
	p.NextOffset = nil
	p.SnapshotDigest = "invalid"
	if _, e := EncodePage(p); e != ErrInvalidSnapshot {
		t.Fatal("invalid digest", e)
	}
}
