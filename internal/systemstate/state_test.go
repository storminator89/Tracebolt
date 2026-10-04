package systemstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const testBinding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func openTestState(t *testing.T) (*State, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux permission policy")
	}
	dir := filepath.Join(t.TempDir(), "private", "sender")
	s, err := Open(dir, testBinding)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func reopenTestState(t *testing.T, dir string) *State {
	t.Helper()
	s, err := Open(dir, testBinding)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}
func requireSequence(t *testing.T, s *State, want uint64) {
	t.Helper()
	n, err := s.NextSequence()
	if err != nil || n != want {
		t.Fatalf("sequence = %d, %v; want %d", n, err, want)
	}
}
func putState(t *testing.T, dir string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "system-state.json"), raw, 0600); err != nil {
		t.Fatal("fixture write failed")
	}
}

func TestExactPendingBytesSurviveReopenAndCopies(t *testing.T) {
	s, dir := openTestState(t)
	body := []byte(" \n{\"sequence\":1,\"collectedAt\":\"2000-01-01T00:00:00Z\",\"observation\":\"private-example\"}\t\n")
	want := bytes.Clone(body)
	requireSequence(t, s, 1)
	p, err := s.Stage(1, body)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	hash := sha256.Sum256(want)
	if p.Sequence != 1 || p.Digest != hex.EncodeToString(hash[:]) || !bytes.Equal(p.Body(), want) {
		t.Fatal("staged request metadata or exact bytes changed")
	}
	body[1] = 'X'
	copyBody := p.Body()
	copyBody[2] = 'X'
	p.Sequence = 9
	p.Digest = "altered"
	stored, err := s.Pending()
	if err != nil || stored.Sequence != 1 || !bytes.Equal(stored.Body(), want) {
		t.Fatal("caller mutated retained request")
	}
	if err = s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s = reopenTestState(t, dir)
	stored, err = s.Pending()
	if err != nil || stored == nil || stored.Sequence != 1 || !bytes.Equal(stored.Body(), want) {
		t.Fatal("pending bytes did not survive reopen")
	}
	requireSequence(t, s, 2)
}

func TestAcknowledgmentDiscardAndMonotonicSequence(t *testing.T) {
	s, dir := openTestState(t)
	requireSequence(t, s, 1)
	requireSequence(t, s, 1)
	_, err := s.Stage(0, []byte(`{}`))
	requireError(t, err, ErrSequence)
	_, err = s.Stage(2, []byte(`{}`))
	requireError(t, err, ErrSequence)
	p, err := s.Stage(1, []byte(`{"sequence":1}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Stage(2, []byte(`{"sequence":2}`))
	requireError(t, err, ErrPending)
	requireError(t, s.Acknowledge(strings.Repeat("b", 64)), ErrDigest)
	if pending, _ := s.Pending(); pending == nil {
		t.Fatal("wrong acknowledgment cleared request")
	}
	if err = s.Acknowledge(p.Digest); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Acknowledge(p.Digest), ErrDigest)
	_ = s.Close()
	s = reopenTestState(t, dir)
	if pending, err := s.Pending(); err != nil || pending != nil {
		t.Fatal("acknowledgment did not persist")
	}
	requireSequence(t, s, 2)
	p, err = s.Stage(2, []byte(`{"sequence":2}`))
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Discard("bad"), ErrDigest)
	if err = s.Discard(p.Digest); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = reopenTestState(t, dir)
	requireSequence(t, s, 3)
	if pending, _ := s.Pending(); pending != nil {
		t.Fatal("discard did not persist")
	}
}

func TestBindingCannotChangeOrBeMalformed(t *testing.T) {
	s, dir := openTestState(t)
	_ = s.Close()
	before, _ := os.ReadFile(filepath.Join(dir, "system-state.json"))
	for _, binding := range []string{"", "a", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("b", 64)} {
		got, err := Open(dir, binding)
		if got != nil {
			_ = got.Close()
			t.Fatal("mismatched binding opened")
		}
		requireError(t, err, ErrBinding)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "system-state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("binding mismatch modified retained state")
	}
	_ = reopenTestState(t, dir)
}

func TestBodyLimitsAndJSON(t *testing.T) {
	s, _ := openTestState(t)
	for _, raw := range [][]byte{nil, []byte(""), []byte("not-json"), []byte("{} {}"), []byte("{\"x\":"), bytes.Repeat([]byte(" "), MaxBodyBytes+1)} {
		_, err := s.Stage(1, raw)
		requireError(t, err, ErrBody)
		requireSequence(t, s, 1)
	}
	body := []byte(`"` + strings.Repeat("x", MaxBodyBytes-2) + `"`)
	p, err := s.Stage(1, body)
	if err != nil || !bytes.Equal(p.Body(), body) {
		t.Fatal("maximum permitted body rejected")
	}
	raw, err := encodeRecord(s.inner.record)
	if err != nil || len(raw) > MaxStateBytes {
		t.Fatal("maximum body exceeds state bound")
	}
}

func TestStrictStateJSONRejectsCorruption(t *testing.T) {
	base := `{"version":1,"binding":"` + testBinding + `","lastSequence":0,"pending":null}`
	hash := sha256.Sum256([]byte(`{}`))
	pending := `{"version":1,"binding":"` + testBinding + `","lastSequence":1,"pending":{"sequence":1,"digest":"` + hex.EncodeToString(hash[:]) + `","body":"e30="}}`
	cases := []string{
		"", " ", "not-json", "null", "[]", base + "{}", base[:len(base)-1],
		strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(base, `"version":1`, `"Version":1`, 1),
		strings.Replace(base, `"version":1`, `"version":2`, 1),
		strings.Replace(base, `"version":1`, `"version":null`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":null`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":-1`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":9223372036854775808`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":18446744073709551615`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":18446744073709551616`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":1.0`, 1),
		strings.Replace(base, `"lastSequence":0`, `"lastSequence":"0"`, 1),
		strings.Replace(base, `"lastSequence":0,`, "", 1),
		strings.Replace(base, `"pending":null`, `"pending":null,"extra":0`, 1),
		strings.Replace(base, testBinding, strings.ToUpper(testBinding), 1),
		strings.Replace(base, `"pending":null`, `"pending":{}`, 1),
		strings.Replace(pending, `"sequence":1`, `"sequence":1,"sequence":1`, 1),
		strings.Replace(pending, `"sequence":1`, `"sequence":0`, 1),
		strings.Replace(pending, `"sequence":1`, `"sequence":2`, 1),
		strings.Replace(pending, `"body":"e30="`, `"Body":"e30="`, 1),
		strings.Replace(pending, `"body":"e30="`, `"body":null`, 1),
		strings.Replace(pending, `"body":"e30="`, `"body":"e3A="`, 1),
		strings.Replace(pending, `"body":"e30="`, `"body":"e31="`, 1),
		strings.Replace(pending, `"body":"e30="`, `"body":"e30=\n"`, 1),
		strings.Replace(pending, hex.EncodeToString(hash[:]), testBinding, 1),
	}
	for i, raw := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) { _, err := decodeRecord([]byte(raw)); requireError(t, err, ErrCorrupt) })
	}
	for _, raw := range []string{base, pending} {
		if _, err := decodeRecord([]byte(raw)); err != nil {
			t.Fatal("valid strict state rejected")
		}
	}
}

func TestCorruptOversizeStateAndSequenceExhaustion(t *testing.T) {
	for _, kind := range []string{"truncated", "oversized", "exhausted"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := openTestState(t)
			_ = s.Close()
			if kind == "exhausted" {
				raw, _ := encodeRecord(diskRecord{Version: stateVersion, Binding: testBinding, LastSequence: math.MaxInt64})
				putState(t, dir, raw)
				s = reopenTestState(t, dir)
				_, err := s.NextSequence()
				requireError(t, err, ErrSequence)
				_, err = s.Stage(0, []byte(`{}`))
				requireError(t, err, ErrSequence)
				return
			}
			raw := []byte(`{"version":`)
			if kind == "oversized" {
				raw = bytes.Repeat([]byte("x"), MaxStateBytes+1)
			}
			putState(t, dir, raw)
			_, err := Open(dir, testBinding)
			requireError(t, err, ErrCorrupt)
			after, _ := os.ReadFile(filepath.Join(dir, "system-state.json"))
			if !bytes.Equal(raw, after) {
				t.Fatal("corrupt state was modified")
			}
		})
	}
}

func TestFormattingAndJSONNeverDumpObservation(t *testing.T) {
	s, _ := openTestState(t)
	const secret = "private-observation-example"
	p, err := s.Stage(1, []byte(`{"observation":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{p, &p, s, *s, []Pending{p}, struct{ Value Pending }{p}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(format, v), secret) {
				t.Fatal("format leaked observation")
			}
		}
		raw, err := json.Marshal(v)
		if err != nil || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("observation")) {
			t.Fatal("JSON leaked observation or failed")
		}
	}
}

func TestLastWireSequenceCanBeConsumedOnce(t *testing.T) {
	s, dir := openTestState(t)
	_ = s.Close()
	raw, _ := encodeRecord(diskRecord{Version: stateVersion, Binding: testBinding, LastSequence: MaxSequence - 1})
	putState(t, dir, raw)
	s = reopenTestState(t, dir)
	requireSequence(t, s, MaxSequence)
	p, err := s.Stage(MaxSequence, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Acknowledge(p.Digest); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = reopenTestState(t, dir)
	_, err = s.NextSequence()
	requireError(t, err, ErrSequence)
	_, err = s.Stage(MaxSequence+1, []byte(`{}`))
	requireError(t, err, ErrSequence)
}

func TestConcurrentStageAndStateCopies(t *testing.T) {
	s, _ := openTestState(t)
	copyState := *s
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := copyState.Stage(1, []byte(`{}`)); results <- err }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else {
			requireError(t, err, ErrPending)
		}
	}
	if wins != 1 {
		t.Fatal("multiple requests staged for one sequence")
	}
	if err := copyState.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := s.Pending()
	requireError(t, err, ErrClosed)
	if err = s.Close(); err != nil {
		t.Fatal("repeat close failed")
	}
	var zero State
	_, err = zero.NextSequence()
	requireError(t, err, ErrClosed)
	var nilState *State
	if nilState.Close() != nil {
		t.Fatal("nil close failed")
	}
	_, err = nilState.Stage(1, []byte(`{}`))
	requireError(t, err, ErrClosed)
}

func TestNonLinuxExplicitlyUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux policy")
	}
	_, err := Open(t.TempDir(), testBinding)
	requireError(t, err, ErrUnsupported)
}
