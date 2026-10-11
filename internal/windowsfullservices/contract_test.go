package windowsfullservices

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func testConsent() Consent {
	return Consent{ConsentVersion, Scope, strings.Repeat("a", 64), strings.Repeat("b", 32), 1, true, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
}
func testRows(n int) []Row {
	rows := make([]Row, n)
	for i := range rows {
		name := fmt.Sprintf("InventedService%05d", i)
		display, state, pid := "Invented display <script>", "running", uint32(i)
		rows[i] = Row{name, &display, "observed", &state, "observed", &pid, "observed"}
	}
	return rows
}
func testCapture(n int) Capture {
	c := testConsent()
	return Capture{StartedAt: c.ChangedAt.Add(time.Minute), FinishedAt: c.ChangedAt.Add(time.Minute + time.Second), Rows: testRows(n), Complete: true}
}

const testDevice = "agent_11111111111111111111111111111111"

type testStorage struct {
	files  map[string][]byte
	writes []string
	fail   string
}

func newTestStorage() *testStorage { return &testStorage{files: map[string][]byte{}} }
func (s *testStorage) Read(n string) ([]byte, error) {
	b, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (s *testStorage) Write(n string, b []byte) error {
	if n == s.fail {
		return errors.New("injected storage failure")
	}
	s.files[n] = bytes.Clone(b)
	s.writes = append(s.writes, n)
	return nil
}
func (s *testStorage) Close() error { return nil }
func receiptFor(raw []byte, at time.Time) []byte {
	m, _ := DecodeMessage(raw)
	status := "accepted"
	if m.Operation == "chunk" && m.Index == m.Manifest.ChunkCount-1 {
		status = "complete"
	}
	b, _ := json.Marshal(Receipt{ReceiptVersion, m.Operation, m.DeviceID, m.Consent.GrantID, m.Consent.Revision, m.Sequence, Hash(raw), m.Index, status, at})
	return b
}
func TestFullServiceGenerationBeyondBothLegacyCaps(t *testing.T) {
	for _, n := range []int{0, 513, 2049, 8192} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			capture := testCapture(n)
			messages, e := Build(testDevice, testConsent(), 7, capture)
			if e != nil {
				t.Fatal(e)
			}
			all := []Row{}
			for i, m := range messages {
				raw, e := EncodeMessage(m)
				if e != nil || len(raw) > MaxChunkBytes || len(m.Rows) > MaxChunkRows || m.Index != i || m.Offset != len(all) {
					t.Fatal("bounded chunk invalid", i, e)
				}
				decoded, e := DecodeMessage(raw)
				if e != nil || decoded.Manifest.GenerationID != m.Manifest.GenerationID {
					t.Fatal(e)
				}
				all = append(all, m.Rows...)
			}
			hash, size, e := RowsDigest(all)
			if e != nil || len(all) != n || hash != messages[0].Manifest.RowsSHA256 || size != messages[0].Manifest.RowsBytes {
				t.Fatal("not a full frozen generation")
			}
			if !messages[0].Manifest.CaptureStartedAt.Equal(capture.StartedAt) || !messages[0].Manifest.ExpiresAt.Equal(capture.StartedAt.Add(Retention)) {
				t.Fatal("original age changed")
			}
		})
	}
}
func TestLongUnicodeAndMissingFieldsRemainIdentifiable(t *testing.T) {
	c := testCapture(1)
	c.Rows[0].Name = strings.Repeat("界", 256)
	c.Rows[0].DisplayName = nil
	c.Rows[0].DisplayNameQuality = "unavailable"
	c.Rows[0].State = nil
	c.Rows[0].StateQuality = "unavailable"
	c.Rows[0].PID = nil
	c.Rows[0].PIDQuality = "unavailable"
	m, e := Build(testDevice, testConsent(), 1, c)
	if e != nil || len(m[0].Rows[0].Name) != 768 || m[0].Rows[0].State != nil {
		t.Fatal("valid native text or unknown field dropped", e)
	}
	for _, pair := range [][2]string{{"Service", "service"}, {"Σ", "ς"}, {"K", "K"}} {
		c.Rows = testRows(2)
		c.Rows[0].Name = pair[0]
		c.Rows[1].Name = pair[1]
		if _, e = Build(testDevice, testConsent(), 1, c); e == nil {
			t.Fatal("case-folded duplicate retained", pair)
		}
	}
}
func TestMessagesRejectAmbiguityAndChangedBindings(t *testing.T) {
	ms, e := Build(testDevice, testConsent(), 1, testCapture(2))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeMessage(ms[0])
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"index":0`), []byte(`"index":0,"index":0`), 1), bytes.Replace(raw, []byte(`"index":0`), []byte(`"index":0,"extra":true`), 1), bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1.0`), 1)} {
		if _, e := DecodeMessage(bad); e == nil {
			t.Fatal("ambiguous message accepted")
		}
	}
	for _, change := range []func(*Message){func(m *Message) { m.ManifestSHA256 = strings.Repeat("0", 64) }, func(m *Message) { m.Consent.Revision++ }, func(m *Message) { m.Offset = 1 }, func(m *Message) { m.Consent.Enabled = false }, func(m *Message) { m.Rows[0].Name = "" }} {
		copyRaw := bytes.Clone(raw)
		m, _ := DecodeMessage(copyRaw)
		change(&m)
		if ValidateMessage(m) == nil {
			t.Fatal("changed binding accepted")
		}
	}
}
func TestResumedEnumerationCompleteAndFailureTruth(t *testing.T) {
	at := testConsent().ChangedAt.Add(time.Minute)
	rows := testRows(2049)
	calls := 0
	tokens := []uint32{700, 12, 99, 4, 33, 1}
	out, e := collectPages(context.Background(), func(_ context.Context, resume uint32) (enumerationPage, error) {
		if calls > 0 && resume != tokens[calls-1] {
			t.Fatal("opaque token changed")
		}
		start := calls * 350
		end := start + 350
		if end > len(rows) {
			end = len(rows)
		}
		p := enumerationPage{rows: rows[start:end], workBytes: NativePageBytes, more: end < len(rows)}
		if p.more {
			p.next = tokens[calls]
		}
		calls++
		return p, nil
	}, func() time.Time { return at })
	if e != nil || !out.Complete || len(out.Rows) != 2049 || calls != 6 {
		t.Fatal("resume lost rows", calls, len(out.Rows), e)
	}
	cases := []struct {
		name, reason string
		read         enumerate
	}{
		{"denied", "access_denied", func(context.Context, uint32) (enumerationPage, error) { return enumerationPage{}, ErrDenied }},
		{"malformed", "malformed_source", func(context.Context, uint32) (enumerationPage, error) {
			return enumerationPage{rows: []Row{{Name: ""}}, workBytes: NativePageBytes}, nil
		}},
		{"repeated", "source_changed", func(context.Context, uint32) (enumerationPage, error) {
			return enumerationPage{rows: testRows(1), more: true, next: 0, workBytes: NativePageBytes}, nil
		}},
		{"no-progress", "source_changed", func(context.Context, uint32) (enumerationPage, error) {
			return enumerationPage{rows: []Row{}, more: true, next: 12, workBytes: NativePageBytes}, nil
		}},
		{"rows", "resource_limit", func(context.Context, uint32) (enumerationPage, error) {
			return enumerationPage{rows: testRows(MaxRows + 1), workBytes: NativePageBytes}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, e := collectPages(context.Background(), tc.read, func() time.Time { return at })
			if e == nil || out.Complete || len(out.Rows) != 0 || out.Reason != tc.reason {
				t.Fatal("failed prefix promoted", out.Reason, e)
			}
		})
	}
	out, e = collectPages(context.Background(), func(context.Context, uint32) (enumerationPage, error) {
		return enumerationPage{rows: []Row{}, workBytes: NativePageBytes}, nil
	}, func() time.Time { return at })
	if e != nil || !out.Complete || len(out.Rows) != 0 {
		t.Fatal("healthy empty not positive")
	}
}
func TestStateExactRetryRestartDisableExpiryAndUsedFloor(t *testing.T) {
	st := newTestStorage()
	c := testConsent()
	if InitializeState(st, testDevice, c.SenderBinding) != nil {
		t.Fatal("init")
	}
	s, e := OpenState(st, testDevice, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	at := c.ChangedAt.Add(time.Minute)
	if _, e = s.Reserve(c, at); e != nil {
		t.Fatal(e)
	}
	cap := testCapture(2049)
	if e = s.Finish(cap, nil, cap.FinishedAt); e != nil {
		t.Fatal(e)
	}
	raw, status, e := s.Next(c, cap.FinishedAt)
	if e != nil || status != "pending" {
		t.Fatal(status, e)
	}
	pack := bytes.Clone(st.files["pack.json"])
	// Loss before ACK and a clean restart cannot recollect or refresh any bytes.
	s, e = OpenState(st, testDevice, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	retry, _, e := s.Next(c, cap.FinishedAt.Add(time.Second))
	if e != nil || !bytes.Equal(raw, retry) || !bytes.Equal(pack, st.files["pack.json"]) {
		t.Fatal("lost-ack restart recaptured")
	}
	disabled := c
	disabled.Enabled = false
	disabled.Revision++
	disabled.ChangedAt = cap.FinishedAt.Add(time.Second)
	if b, status, e := s.Next(disabled, disabled.ChangedAt); e != nil || status != "disabled" || b != nil || s.Floor() != 1 {
		t.Fatal("disable mutated or delivered pending")
	}
	reenabled := disabled
	reenabled.Enabled = true
	reenabled.Revision++
	reenabled.GrantID = strings.Repeat("c", 32)
	reenabled.ChangedAt = disabled.ChangedAt.Add(time.Second)
	if b, status, e := s.Next(reenabled, reenabled.ChangedAt); e != nil || status != "discarded_unconsented" || b != nil || s.Floor() != 1 {
		t.Fatal("reenable adopted old pack")
	}
	if _, e = s.Reserve(reenabled, at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	cap.StartedAt = at.Add(time.Minute)
	cap.FinishedAt = cap.StartedAt.Add(time.Second)
	if e = s.Finish(cap, nil, cap.FinishedAt); e != nil {
		t.Fatal(e)
	}
	if b, status, e := s.Next(reenabled, cap.StartedAt.Add(Retention)); e != nil || status != "expired" || b != nil || s.Floor() != 2 {
		t.Fatal("expired pack was revived")
	}
	delete(st.files, "sender.json")
	if _, e = OpenState(st, testDevice, c.SenderBinding); e == nil {
		t.Fatal("missing used floor reset")
	}
}
func TestCapturedCrashRetainsFailureAndFrozenPackRecovery(t *testing.T) {
	for _, withPack := range []bool{false, true} {
		t.Run(fmt.Sprint(withPack), func(t *testing.T) {
			c := testConsent()
			st := newTestStorage()
			InitializeState(st, testDevice, c.SenderBinding)
			s, _ := OpenState(st, testDevice, c.SenderBinding)
			cap := testCapture(1)
			s.Reserve(c, cap.StartedAt)
			claimed := bytes.Clone(st.files["sender.json"])
			if withPack {
				if e := s.Finish(cap, nil, cap.FinishedAt); e != nil {
					t.Fatal(e)
				}
				st.files["sender.json"] = claimed
			}
			s, e := OpenState(st, testDevice, c.SenderBinding)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.Recover(cap.FinishedAt); e != nil {
				t.Fatal(e)
			}
			raw, _, e := s.Next(c, cap.FinishedAt)
			if e != nil {
				t.Fatal(e)
			}
			m, _ := DecodeMessage(raw)
			want := "failure"
			if withPack {
				want = "chunk"
			}
			if m.Operation != want || m.Sequence != 1 {
				t.Fatal("capture crash reissued", m.Operation)
			}
			if e = s.Acknowledge(raw, receiptFor(raw, cap.FinishedAt), cap.FinishedAt); e != nil {
				t.Fatal(e)
			}
			if s.Pending() || s.Floor() != 1 {
				t.Fatal("floor cleared")
			}
		})
	}
}
func TestPendingPackBudgetAndPoisonedWrites(t *testing.T) {
	c := testConsent()
	st := newTestStorage()
	InitializeState(st, testDevice, c.SenderBinding)
	s, _ := OpenState(st, testDevice, c.SenderBinding)
	cap := testCapture(MaxRows)
	for i := range cap.Rows {
		v := strings.Repeat("<", 256)
		cap.Rows[i].DisplayName = &v
	}
	s.Reserve(c, cap.StartedAt)
	if e := s.Finish(cap, nil, cap.FinishedAt); e != nil {
		t.Fatal(e)
	}
	raw, _, _ := s.Next(c, cap.FinishedAt)
	m, _ := DecodeMessage(raw)
	if m.Operation != "failure" || m.Reason != "resource_limit" || len(st.files["pack.json"]) > 8192 {
		t.Fatal("source budget wrote oversized pack")
	}
	st.fail = "sender.json"
	if s.Acknowledge(raw, receiptFor(raw, cap.FinishedAt), cap.FinishedAt) == nil {
		t.Fatal("write failure ignored")
	}
	st.fail = ""
	if _, _, e := s.Next(c, cap.FinishedAt); e == nil {
		t.Fatal("poisoned state reused")
	}
}
func BenchmarkBuildFullServices8192(b *testing.B) {
	c := testConsent()
	capture := testCapture(8192)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := Build(testDevice, c, 1, capture); e != nil {
			b.Fatal(e)
		}
	}
}

func TestTerminalResumeAndPartialDenialNeverPromotePrefix(t *testing.T) {
	at := testConsent().ChangedAt.Add(time.Minute)
	out, e := collectPages(context.Background(), func(context.Context, uint32) (enumerationPage, error) {
		return enumerationPage{rows: testRows(1), next: 99, more: false, workBytes: NativePageBytes}, nil
	}, func() time.Time { return at })
	if e == nil || out.Complete || len(out.Rows) != 0 || out.Reason != "malformed_source" {
		t.Fatal("contradictory EOF promoted")
	}
	calls := 0
	out, e = collectPages(context.Background(), func(context.Context, uint32) (enumerationPage, error) {
		calls++
		if calls == 1 {
			return enumerationPage{rows: testRows(1), next: 19, more: true, workBytes: NativePageBytes}, nil
		}
		return enumerationPage{}, ErrDenied
	}, func() time.Time { return at })
	if e == nil || out.Complete || len(out.Rows) != 0 || out.Reason != "access_denied" {
		t.Fatal("denied prefix promoted")
	}
}
