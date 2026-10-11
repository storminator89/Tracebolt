package windowshistorystate

import (
	"bytes"
	"errors"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventstate"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"os"
	"strings"
	"testing"
	"time"
)

type memory struct {
	values    map[string][]byte
	writes    int
	ambiguous bool
}

func (m *memory) Read(n string) ([]byte, error) {
	b, ok := m.values[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (m *memory) Write(n string, b []byte) error {
	m.writes++
	m.values[n] = bytes.Clone(b)
	if m.ambiguous {
		return ErrState
	}
	return nil
}
func fixture(t *testing.T) (*memory, windowshistoryrequest.LocalContext, windowshistoryrequest.Consent, windowshistoryrequest.Description, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	l := windowshistoryrequest.LocalContext{SenderBinding: strings.Repeat("a", 64), Profile: "tls", DeviceID: "agent_" + strings.Repeat("b", 32), CertificateHash: strings.Repeat("c", 64)}
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: l.SenderBinding, GrantID: strings.Repeat("d", 32), Profile: l.Profile, Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	r, e := windowshistoryrequest.NewSearch(l.DeviceID, l.CertificateHash, 7, c.GrantID, windowseventhistory.Search{Channel: "System", Start: now.Add(-48 * time.Hour), End: now.Add(-24 * time.Hour)}, now)
	if e != nil {
		t.Fatal(e)
	}
	reports, _ := NewReports(l)
	raw, _ := EncodeReports(reports)
	consumed, _ := NewConsumption(l)
	con, _ := EncodeConsumption(consumed)
	return &memory{values: map[string][]byte{"reports.json": raw, "consumed.json": con}}, l, c, r.Description, now
}
func TestHistoryExactCapabilityAndConsumeOnceFloors(t *testing.T) {
	m, l, c, d, now := fixture(t)
	raw, e := StageCapability(m, l, c, now)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := StageCapability(m, l, c, now.Add(time.Minute))
	if e != nil || !bytes.Equal(raw, retry) || m.writes != 1 {
		t.Fatal("capability age refreshed")
	}
	cap, e := windowshistorywire.DecodeCapability(raw)
	if e != nil || cap.CollectedAt != now {
		t.Fatal("original capture lost")
	}
	policy, e := windowshistoryrequest.Authorize(d, c, l, now)
	if e != nil {
		t.Fatal(e)
	}
	if BeginClaim(m, l, d, c, policy, now) != nil || VerifyAttempt(m, l, d, policy) != nil || Consume(m, l, d, c, policy, now) != nil {
		t.Fatal("durable attempt/consume failed")
	}
	reopened := &memory{values: m.values}
	if !errors.Is(BeginClaim(reopened, l, d, c, policy, now), ErrConsumed) || !errors.Is(Consume(reopened, l, d, c, policy, now), ErrConsumed) {
		t.Fatal("restart reread permitted")
	}
	for _, raw := range m.values {
		if bytes.Contains(raw, []byte("System")) || bytes.Contains(raw, []byte("searchReceipt")) {
			t.Fatal("query metadata persisted")
		}
	}
	old := windowseventrequest.LocalContext{SenderBinding: l.SenderBinding, Profile: l.Profile, DeviceID: l.DeviceID, CertificateHash: l.CertificateHash}
	if _, e := windowseventstate.ReadReports(m, old); e == nil {
		t.Fatal("old content state accepted history ledger")
	}
}
func TestHistoryMissingUsedAndAmbiguousStateCannotBeReinitialized(t *testing.T) {
	for _, file := range []string{"reports.json", "consumed.json"} {
		m, l, c, d, now := fixture(t)
		policy, _ := windowshistoryrequest.Authorize(d, c, l, now)
		delete(m.values, file)
		if file == "reports.json" {
			if _, e := StageCapability(m, l, c, now); e == nil {
				t.Fatal("missing reports repaired")
			}
		} else if Consume(m, l, d, c, policy, now) == nil {
			t.Fatal("missing consumed repaired")
		}
		if m.writes != 0 {
			t.Fatal("missing used state changed")
		}
	}
	m, l, c, d, now := fixture(t)
	policy, _ := windowshistoryrequest.Authorize(d, c, l, now)
	m.ambiguous = true
	if BeginClaim(m, l, d, c, policy, now) == nil || Consume(m, l, d, c, policy, now) == nil {
		t.Fatal("ambiguous commit released authority")
	}
	m.ambiguous = false
	if !errors.Is(BeginClaim(m, l, d, c, policy, now), ErrConsumed) || !errors.Is(Consume(m, l, d, c, policy, now), ErrConsumed) {
		t.Fatal("ambiguous commit retried as new")
	}
}
