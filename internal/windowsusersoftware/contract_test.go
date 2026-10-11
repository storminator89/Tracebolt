package windowsusersoftware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, n int) (string, Consent, Capture) {
	t.Helper()
	at := time.Date(2026, 10, 11, 20, 0, 0, 0, time.UTC)
	device := "agent_" + strings.Repeat("a", 32)
	c := Consent{SchemaVersion: ConsentVersion, Scope: Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: at}
	cp := Capture{AccountContextID: strings.Repeat("d", 64), AccountLabel: "Selected account dddddddd", CaptureNonce: strings.Repeat("e", 64), HKCUStatus: "complete", MSIXStatus: "unsupported", StartedAt: at, FinishedAt: at, Complete: true, Rows: []Row{}}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("Synthetic %04d", i)
		cp.Rows = append(cp.Rows, Row{RegistrationID: fmt.Sprintf("%064x", i+1), Source: "hkcu", Name: &name, NameQuality: "observed", VersionQuality: "unavailable", PublisherQuality: "unavailable"})
	}
	return device, c, cp
}
func TestAccountSourceAndCoverageContract(t *testing.T) {
	device, c, cp := fixture(t, 257)
	m, e := Build(device, c, 1, cp)
	if e != nil || len(m) != 3 {
		t.Fatal(len(m), e)
	}
	if m[0].Manifest.Coverage != PartialCoverage || m[0].Manifest.RowCount != 257 {
		t.Fatal("partial source truth")
	}
	cp.MSIXStatus = "complete"
	both, e := Build(device, c, 2, cp)
	if e != nil || both[0].Manifest.Coverage != Coverage {
		t.Fatal(e)
	}
	cp.HKCUStatus = "resource_limit"
	if _, e = Build(device, c, 3, cp); e == nil {
		t.Fatal("accepted truncated source")
	}
	cp.Rows = []Row{}
	empty, e := Build(device, c, 3, cp)
	if e != nil || empty[0].Manifest.Coverage != PartialCoverage {
		t.Fatal(e)
	}
	a, _ := AccountContextID(device, "S-1-5-21-1000")
	b, _ := AccountContextID(device, "S-1-5-21-1001")
	other, _ := AccountContextID("agent_"+strings.Repeat("f", 32), "S-1-5-21-1000")
	if a == b || a == other || !ValidHex(a, 64) {
		t.Fatal("account domain collision")
	}
	hkcu, _ := RegistrationID("hkcu", []uint16{'A'})
	msix, _ := RegistrationID("msix", []uint16{'A'})
	if hkcu == msix {
		t.Fatal("source identity reused")
	}
	for _, bad := range [][]uint16{{0}, {0xd800}, {0xdc00}} {
		if _, e := RegistrationID("hkcu", bad); e == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
func TestBoundsAndStrictSelectedAccountProtocol(t *testing.T) {
	device, c, cp := fixture(t, MaxRows)
	messages, e := Build(device, c, 1, cp)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		raw, e := EncodeMessage(m)
		if e != nil || len(raw) > MaxChunkBytes || len(m.Rows) > MaxChunkRows {
			t.Fatal(e)
		}
		if _, e = DecodeMessage(append(raw, ' ')); e == nil {
			t.Fatal("noncanonical request")
		}
	}
	cp.Rows = append(cp.Rows, cp.Rows[0])
	if _, e = Build(device, c, 2, cp); e == nil {
		t.Fatal("row limit")
	}
	cp.Rows = cp.Rows[:1]
	cp.CaptureNonce = "caller-choice"
	if _, e = Build(device, c, 2, cp); e == nil {
		t.Fatal("weak nonce")
	}
	raw, _ := EncodeMessage(messages[0])
	var generic map[string]any
	json.Unmarshal(raw, &generic)
	generic["sid"] = "S-1-5-21-1000"
	bad, _ := json.Marshal(generic)
	if _, e = DecodeMessage(bad); e == nil {
		t.Fatal("SID wire field accepted")
	}
	if bytes.Contains(raw, []byte("registryView")) || bytes.Contains(raw, []byte("historyScope")) {
		t.Fatal("machine contract leaked")
	}
	for _, q := range []Query{{Source: "machine", Sort: "name-asc", Limit: 1}, {AccountContextID: "wrong", Sort: "name-asc", Limit: 1}, {Sort: "view-asc", Limit: 1}} {
		if ValidateQuery(q) == nil {
			t.Fatal("query authority mixing")
		}
	}
}

type memoryStorage map[string][]byte

func (m memoryStorage) Read(k string) ([]byte, error) {
	b, ok := m[k]
	if !ok {
		return nil, ErrState
	}
	return bytes.Clone(b), nil
}
func (m memoryStorage) Write(k string, b []byte) error { m[k] = bytes.Clone(b); return nil }
func (m memoryStorage) Close() error                   { return nil }
func TestReserveConsumesAndBindsAccountBeforeFinish(t *testing.T) {
	device, c, cp := fixture(t, 1)
	mem := memoryStorage{}
	if e := InitializeState(mem, device, c.SenderBinding); e != nil {
		t.Fatal(e)
	}
	s, e := OpenState(mem, device, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	raw, status, e := s.Next(c, cp.StartedAt)
	if e != nil || raw != nil || status != "awaiting_foreground_capture" {
		t.Fatal("automatic capture requested", status, e)
	}
	seq, e := s.ReserveCapture(c, cp.AccountContextID, cp.AccountLabel, cp.CaptureNonce, cp.StartedAt)
	if e != nil || seq != 1 {
		t.Fatal(e)
	}
	cp.AccountContextID = strings.Repeat("f", 64)
	if e = s.Finish(cp, nil, cp.FinishedAt); e != nil {
		t.Fatal(e)
	}
	raw, _, e = s.Next(c, cp.FinishedAt)
	if e != nil {
		t.Fatal(e)
	}
	m, e := DecodeMessage(raw)
	if e != nil || m.Operation != "failure" || m.AccountContextID != strings.Repeat("d", 64) || m.Reason != "malformed_source" {
		t.Fatal("account transplant", m.Operation, e)
	}
	opened, e := OpenState(mem, device, c.SenderBinding)
	if e != nil || opened.Floor() != 1 {
		t.Fatal(e)
	}
	again, _, _ := opened.Next(c, cp.StartedAt.Add(time.Second))
	if !bytes.Equal(raw, again) {
		t.Fatal("retry changed")
	}
}
func TestInterruptedReservationNeverRecaptures(t *testing.T) {
	device, c, cp := fixture(t, 0)
	mem := memoryStorage{}
	InitializeState(mem, device, c.SenderBinding)
	s, _ := OpenState(mem, device, c.SenderBinding)
	s.ReserveCapture(c, cp.AccountContextID, cp.AccountLabel, cp.CaptureNonce, cp.StartedAt)
	s, e := OpenState(mem, device, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	raw, status, e := s.Next(c, cp.StartedAt.Add(time.Second))
	m, de := DecodeMessage(raw)
	if e != nil || de != nil || status != "pending" || m.Operation != "failure" || m.Sequence != 1 || m.AccountContextID != cp.AccountContextID {
		t.Fatal("restart recapture", e, de)
	}
}

func TestSelectedAccountScopeCannotPromoteMachineOrHistory(t *testing.T) {
	device, c, _ := fixture(t, 0)
	c.Scope = "windows-complete-machine-software-v1"
	if ValidateConsent(c) == nil {
		t.Fatal("machine scope promoted")
	}
	c.Scope = Scope
	raw, _ := EncodeMessage(Message{SchemaVersion: MessageVersion, Operation: "scope", DeviceID: device, Consent: c})
	var generic map[string]any
	json.Unmarshal(raw, &generic)
	generic["consent"].(map[string]any)["historyScope"] = "windows-machine-software-history-v1"
	bad, _ := json.Marshal(generic)
	if _, e := DecodeMessage(bad); e == nil {
		t.Fatal("history authority admitted")
	}
}
