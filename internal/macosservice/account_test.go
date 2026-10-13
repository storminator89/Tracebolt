package macosservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestAccountLookupUsesOnlyExactLocalReadQueries(t *testing.T) {
	var calls [][]string
	read := func(_ context.Context, args []string) ([]byte, error) {
		calls = append(calls, args)
		if len(calls) == 1 {
			return []byte("PrimaryGroupID: 510\nUniqueID: 511\n"), nil
		}
		return []byte("PrimaryGroupID: 510\n"), nil
	}
	if !inspectDedicatedAccount(context.Background(), 511, 510, read) {
		t.Fatal("exact dedicated account rejected")
	}
	want := [][]string{{"/Local/Default", "-read", "/Users/_traceboltagent", "UniqueID", "PrimaryGroupID"}, {"/Local/Default", "-read", "/Groups/_traceboltagent", "PrimaryGroupID"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unfixed native query: %#v", calls)
	}
}
func TestAccountParserRejectsUncertainOrMultipleIDs(t *testing.T) {
	expected := map[string]int{"UniqueID": 511, "PrimaryGroupID": 510}
	for _, raw := range []string{"", "UniqueID: 511\n", "UniqueID: 511\nPrimaryGroupID: 510", "UniqueID: 511\nPrimaryGroupID: 510\n\n", "UniqueID: 511\nUniqueID: 511\n", "UniqueID: 0511\nPrimaryGroupID: 510\n", "UniqueID: 511 512\nPrimaryGroupID: 510\n", "UniqueID: 511\nPrimaryGroupID: 0\n", "UniqueID: 511\r\nPrimaryGroupID: 510\r\n", "UniqueID: 511\nPrimaryGroupID: 510\nOther: 1\n", strings.Repeat("x", maxAccountOutput+1)} {
		if accountRecordMatches([]byte(raw), expected) {
			t.Fatalf("accepted %q", raw)
		}
	}
	if !accountRecordMatches([]byte("UniqueID: 511\nPrimaryGroupID: 510\n"), expected) {
		t.Fatal("canonical output")
	}
}
func TestAccountLookupFailsClosedBeforeNextRead(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		calls := 0
		read := func(context.Context, []string) ([]byte, error) {
			calls++
			if calls == failAt {
				return nil, errors.New("denied")
			}
			return []byte("UniqueID: 511\nPrimaryGroupID: 510\n"), nil
		}
		if inspectDedicatedAccount(context.Background(), 511, 510, read) || calls != failAt {
			t.Fatal("uncertain lookup continued")
		}
	}
	calls := 0
	read := func(context.Context, []string) ([]byte, error) { calls++; return nil, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if inspectDedicatedAccount(ctx, 511, 510, read) || calls != 0 {
		t.Fatal("canceled lookup")
	}
	if inspectDedicatedAccount(context.Background(), 0, 510, read) || calls != 0 {
		t.Fatal("root lookup")
	}
}

// Pure writer fixture. Never invokes dscl or reads a host account.
func TestNativeAccountOutputIsBounded(t *testing.T) {
	w := &boundedAccountOutput{limit: 4}
	if n, err := w.Write([]byte("123")); err != nil || n != 3 {
		t.Fatal("bounded write")
	}
	if _, err := w.Write([]byte("45")); err == nil || !w.exceeded || w.buffer.String() != "123" {
		t.Fatal("oversized output retained")
	}
	if _, err := w.Write([]byte("4")); err == nil {
		t.Fatal("overflow resumed")
	}
}

func TestAccountCommandArgumentsCannotExpand(t *testing.T) {
	valid := []string{"/Local/Default", "-read", "/Users/" + Account, "UniqueID", "PrimaryGroupID"}
	if !validAccountQuery(valid) {
		t.Fatal("fixed query rejected")
	}
	for i := range valid {
		changed := append([]string{}, valid...)
		changed[i] = "-create"
		if validAccountQuery(changed) {
			t.Fatal("altered query admitted")
		}
	}
	for _, args := range [][]string{nil, {}, valid[:4], append(append([]string{}, valid...), "Password"), {"remote.example", "-read", "/Users/" + Account, "UniqueID", "PrimaryGroupID"}} {
		if validAccountQuery(args) {
			t.Fatal("expanded query admitted")
		}
	}
}
