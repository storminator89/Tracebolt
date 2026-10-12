package windowsusersoftwarelocal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"localrmm/internal/windowsusersoftware"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func fixtureRows(source string, count int) []windowsusersoftware.Row {
	rows := make([]windowsusersoftware.Row, count)
	for i := range rows {
		id, _ := windowsusersoftware.RegistrationID(source, utf16.Encode([]rune(fmt.Sprintf("registration-%d", i))))
		rows[i] = emptyRow(source, id)
	}
	return rows
}
func staticSource(rows []windowsusersoftware.Row) sourceReader {
	return func(context.Context) ([]windowsusersoftware.Row, error) {
		return append([]windowsusersoftware.Row{}, rows...), nil
	}
}
func TestFailedSourcesNeverPromotePrefixesAndPartialIsExplicit(t *testing.T) {
	failed := func(context.Context) ([]windowsusersoftware.Row, error) {
		return fixtureRows("hkcu", 3), windowsusersoftware.ErrDenied
	}
	c := collectSources(context.Background(), failed, staticSource(fixtureRows("msix", 2)), time.Now().UTC())
	if !c.Complete || c.HKCUStatus != "access_denied" || c.MSIXStatus != "complete" || len(c.Rows) != 2 {
		t.Fatalf("bad partial capture: %+v", c)
	}
	for _, r := range c.Rows {
		if r.Source != "msix" {
			t.Fatal("failed prefix retained")
		}
	}
}
func TestSourceMutationDuplicateAndAggregateCapDiscardPrefixes(t *testing.T) {
	n := 0
	changing := func(context.Context) ([]windowsusersoftware.Row, error) { n++; return fixtureRows("hkcu", n), nil }
	if rows, status := stableSource(context.Background(), changing); rows != nil || status != "source_changed" {
		t.Fatalf("mutation promoted: %s", status)
	}
	same := fixtureRows("hkcu", 1)
	dupe := append(same, same[0])
	if rows, status := stableSource(context.Background(), staticSource(dupe)); rows != nil || status == "complete" {
		t.Fatal("duplicates accepted")
	}
	c := collectSources(context.Background(), staticSource(fixtureRows("hkcu", 3000)), staticSource(fixtureRows("msix", 2000)), time.Now().UTC())
	if len(c.Rows) != 0 || c.HKCUStatus != "resource_limit" || c.MSIXStatus != "resource_limit" {
		t.Fatal("aggregate cutoff promoted prefix")
	}
}
func TestEmptySourcesAreCompleteAndOptionalFieldsRemainUnavailable(t *testing.T) {
	c := collectSources(context.Background(), staticSource([]windowsusersoftware.Row{}), staticSource([]windowsusersoftware.Row{}), time.Now().UTC())
	if !c.Complete || c.HKCUStatus != "complete" || c.MSIXStatus != "complete" || c.Rows == nil || len(c.Rows) != 0 {
		t.Fatal("empty enumeration confused with unknown")
	}
	r := fixtureRows("hkcu", 1)[0]
	if windowsusersoftware.ValidateRow(r) != nil || r.Name != nil || r.NameQuality != "unavailable" {
		t.Fatal("unavailable field lost")
	}
}
func TestUTF16NoRepairExpansionOrTruncation(t *testing.T) {
	for _, v := range [][]uint16{{0}, {0xd800}, {0xdc00}, {'x', 0, 'y'}, make([]uint16, 513)} {
		if _, ok := decodeUTF16(v); ok {
			t.Fatalf("accepted invalid %v", v)
		}
	}
	value, ok := decodeUTF16([]uint16{'%', 'P', 'A', 'T', 'H', '%'})
	if !ok || value != "%PATH%" {
		t.Fatal("text was expanded")
	}
}
func TestFailureReasonsRemainFinite(t *testing.T) {
	for _, e := range []error{context.DeadlineExceeded, context.Canceled, windowsusersoftware.ErrBudget, windowsusersoftware.ErrDenied, windowsusersoftware.ErrUnsupported, errChanged, errMalformed, errors.New("private native detail")} {
		if !windowsusersoftware.ValidFailureReason(failureStatus(e)) {
			t.Fatal(e)
		}
	}
}

func TestHKCUEnumeratedExactlyOnceMSIXConsistencyTwice(t *testing.T) {
	h, m := 0, 0
	collectSources(context.Background(), func(context.Context) ([]windowsusersoftware.Row, error) { h++; return []windowsusersoftware.Row{}, nil }, func(context.Context) ([]windowsusersoftware.Row, error) { m++; return []windowsusersoftware.Row{}, nil }, time.Now().UTC())
	if h != 1 || m != 2 {
		t.Fatalf("wrong enumeration count hkcu=%d msix=%d", h, m)
	}
}

func TestHStringCopyUsesExactBoundedOwnedUTF16(t *testing.T) {
	calls := 0
	reader := func(address uintptr, target []byte) (uintptr, error) {
		calls++
		if address != 42 || len(target) != 4 {
			t.Fatal("copy boundary changed")
		}
		binary.LittleEndian.PutUint16(target, 0xd83d)
		binary.LittleEndian.PutUint16(target[2:], 0xde00)
		return uintptr(len(target)), nil
	}
	value, err := copyHString(42, 2, reader)
	if err != nil || value == nil || *value != "😀" || calls != 1 {
		t.Fatalf("copy result %v %v calls=%d", value, err, calls)
	}
	for _, tc := range []struct {
		address uintptr
		length  uint32
	}{{42, windowsusersoftware.MaxFieldUTF16 + 1}, {0, 1}} {
		calls = 0
		value, err = copyHString(tc.address, tc.length, reader)
		if err == nil || value != nil || calls != 0 {
			t.Fatal("invalid length/address reached native reader")
		}
	}
	calls = 0
	value, err = copyHString(0, 0, reader)
	if err != nil || value == nil || *value != "" || calls != 0 {
		t.Fatal("empty HSTRING required a native read")
	}
	value, err = copyHString(42, windowsusersoftware.MaxFieldUTF16, func(_ uintptr, target []byte) (uintptr, error) {
		if len(target) != windowsusersoftware.MaxFieldUTF16*2 {
			t.Fatal("maximum buffer changed")
		}
		for i := 0; i < len(target); i += 2 {
			target[i] = 'a'
		}
		return uintptr(len(target)), nil
	})
	if err != nil || value == nil || *value != strings.Repeat("a", windowsusersoftware.MaxFieldUTF16) {
		t.Fatal("maximum legal field rejected")
	}
	for _, count := range []uintptr{0, 1, 3, 5} {
		value, err = copyHString(42, 2, func(_ uintptr, target []byte) (uintptr, error) { target[0] = 'x'; return count, nil })
		if err == nil || value != nil {
			t.Fatal("partial or oversized byte count exposed a prefix")
		}
	}
	value, err = copyHString(42, 2, func(_ uintptr, target []byte) (uintptr, error) {
		target[0] = 'x'
		return 4, windowsusersoftware.ErrDenied
	})
	if !errors.Is(err, windowsusersoftware.ErrUnavailable) || value != nil {
		t.Fatal("failed copy exposed content")
	}
	for _, unit := range []uint16{0, 0xd800, 0xdc00} {
		value, err = copyHString(42, 1, func(_ uintptr, target []byte) (uintptr, error) {
			binary.LittleEndian.PutUint16(target, unit)
			return 2, nil
		})
		if err == nil || value != nil {
			t.Fatal("invalid UTF16 accepted")
		}
	}
}
