package windowsfullprocesses

import (
	"bytes"
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
		name := "Same process.exe"
		rows[i] = Row{PID: uint32(i), ParentPID: uint32(i / 2), Name: &name, NameQuality: "observed", Threads: 1}
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
func TestFullProcessesGenerationBeyondBothLegacyCaps(t *testing.T) {
	for _, n := range []int{0, 513, 2049, MaxRows} {
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
	for _, change := range []func(*Message){func(m *Message) { m.ManifestSHA256 = strings.Repeat("0", 64) }, func(m *Message) { m.Consent.Revision++ }, func(m *Message) { m.Offset = 1 }, func(m *Message) { m.Consent.Enabled = false }, func(m *Message) { m.Rows[0].NameQuality = "invalid" }} {
		copyRaw := bytes.Clone(raw)
		m, _ := DecodeMessage(copyRaw)
		change(&m)
		if ValidateMessage(m) == nil {
			t.Fatal("changed binding accepted")
		}
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
		cap.Rows[i].Name = &v
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

func TestMaximumCompactProcessesGenerationFitsProtectedPack(t *testing.T) {
	st := newTestStorage()
	c := testConsent()
	capture := testCapture(MaxRows)
	if e := InitializeState(st, testDevice, c.SenderBinding); e != nil {
		t.Fatal(e)
	}
	state, e := OpenState(st, testDevice, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = state.Reserve(c, capture.StartedAt); e != nil {
		t.Fatal(e)
	}
	if e = state.Finish(capture, nil, capture.FinishedAt); e != nil {
		t.Fatal(e)
	}
	if len(st.files["pack.json"]) > MaxPackBytes || MaxPackBytes > 16<<20 {
		t.Fatal("protected pack ceiling exceeded")
	}
	state, e = OpenState(st, testDevice, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	raw, _, e := state.Next(c, capture.FinishedAt)
	if e != nil {
		t.Fatal(e)
	}
	m, e := DecodeMessage(raw)
	if e != nil || m.Operation != "chunk" || m.Manifest.RowCount != MaxRows || m.Manifest.RowsBytes > MaxSourceBytes {
		t.Fatal("maximum capture became failure")
	}
}
