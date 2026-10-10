package windowseventstate

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
)

type memory struct {
	values    map[string][]byte
	writes    int
	fail      bool
	ambiguous bool
}

func (m *memory) Read(n string) ([]byte, error) {
	v, ok := m.values[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(v), nil
}
func (m *memory) Write(n string, b []byte) error {
	m.writes++
	if m.fail {
		return ErrState
	}
	m.values[n] = bytes.Clone(b)
	if m.ambiguous {
		return ErrState
	}
	return nil
}
func fixture(t *testing.T) (*memory, windowseventrequest.LocalContext, windowseventrequest.Consent, windowseventrequest.Description, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	local := windowseventrequest.LocalContext{SenderBinding: strings.Repeat("a", 64), Profile: "tls", DeviceID: "agent_" + strings.Repeat("b", 32), CertificateHash: strings.Repeat("c", 64)}
	c := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: local.SenderBinding, GrantID: strings.Repeat("d", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
	h := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("e", 32), GenerationID: "sample_" + strings.Repeat("f", 32), CollectedAt: now.Add(-time.Minute), Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 7, Level: 2, Provider: "Synthetic", Timestamp: now.Add(-time.Minute)}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	r, e := windowseventrequest.New(local.DeviceID, local.CertificateHash, 4, c.GrantID, h, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, now)
	if e != nil {
		t.Fatal(e)
	}
	reports, e := NewReports(local)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := EncodeReports(reports)
	if e != nil {
		t.Fatal(e)
	}
	consumed, _ := NewConsumption(local)
	con, _ := EncodeConsumption(consumed)
	m := &memory{values: map[string][]byte{"reports.json": raw, "consumed.json": con}}
	return m, local, c, r.Description, now
}
func TestCapabilityExactRetryDisableReenableAndRestart(t *testing.T) {
	m, l, c, _, now := fixture(t)
	raw, e := StageCapability(m, l, c, now)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := StageCapability(m, l, c, now.Add(time.Minute))
	if e != nil || !bytes.Equal(raw, retry) || m.writes != 1 {
		t.Fatal("retry changed original bytes")
	}
	if AcknowledgeCapability(m, l, []byte("wrong")) == nil {
		t.Fatal("acknowledged foreign bytes")
	}
	if AcknowledgeCapability(m, l, raw) != nil {
		t.Fatal("ack failed")
	}
	c.Enabled = false
	off, e := StageCapability(m, l, c, now.Add(2*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	cap, _ := windowseventwire.DecodeCapability(off)
	if cap.Sequence != 2 || cap.Consent.Enabled || cap.Consent.GrantID != c.GrantID {
		t.Fatal("disable reset identity or floor")
	}
	c.Enabled = true
	c.GrantID = strings.Repeat("1", 32)
	on, e := StageCapability(m, l, c, now.Add(3*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	cap, _ = windowseventwire.DecodeCapability(on)
	if cap.Sequence != 3 || !cap.Consent.Enabled {
		t.Fatal("reenable reset sequence")
	}
	reopened := &memory{values: m.values}
	again, e := StageCapability(reopened, l, c, now.Add(4*time.Minute))
	if e != nil || !bytes.Equal(on, again) || reopened.writes != 0 {
		t.Fatal("restart did not retain exact bytes")
	}
}
func TestParentAttemptAndChildConsumptionNeverReplay(t *testing.T) {
	m, l, c, d, now := fixture(t)
	policy, _ := windowseventrequest.Authorize(d, c, l, now)
	if VerifyAttempt(m, l, d, policy) == nil {
		t.Fatal("unattempted request accepted")
	}
	if BeginClaim(m, l, d, c, policy, now) != nil || VerifyAttempt(m, l, d, policy) != nil {
		t.Fatal("attempt not durable")
	}
	if e := BeginClaim(m, l, d, c, policy, now); !errors.Is(e, ErrConsumed) {
		t.Fatal("claim ambiguity retry")
	}
	if Consume(m, l, d, c, policy, now) != nil {
		t.Fatal("consume failed")
	}
	reopened := &memory{values: m.values}
	if e := Consume(reopened, l, d, c, policy, now); !errors.Is(e, ErrConsumed) {
		t.Fatal("restart replay")
	}
	c.Enabled = false
	if Consume(m, l, d, c, policy, now) == nil {
		t.Fatal("disabled consume")
	}
	for _, raw := range m.values {
		if bytes.Contains(raw, []byte("Synthetic")) || bytes.Contains(raw, []byte("18446744073709551615")) {
			t.Fatal("selected event metadata retained")
		}
	}
}
func TestMissingForeignMalformedAndAmbiguousWritesFailClosed(t *testing.T) {
	for _, file := range []string{"reports.json", "consumed.json"} {
		m, l, c, d, now := fixture(t)
		policy, _ := windowseventrequest.Authorize(d, c, l, now)
		delete(m.values, file)
		if file == "reports.json" {
			if _, e := StageCapability(m, l, c, now); e == nil {
				t.Fatal("missing file recreated")
			}
		} else if Consume(m, l, d, c, policy, now) == nil {
			t.Fatal("missing consume recreated")
		}
		if m.writes != 0 {
			t.Fatal("missing used state repaired")
		}
	}
	m, l, c, d, now := fixture(t)
	policy, _ := windowseventrequest.Authorize(d, c, l, now)
	m.ambiguous = true
	if BeginClaim(m, l, d, c, policy, now) == nil {
		t.Fatal("ambiguous attempt reported success")
	}
	m.ambiguous = false
	if !errors.Is(BeginClaim(m, l, d, c, policy, now), ErrConsumed) {
		t.Fatal("ambiguous committed attempt replayed")
	}
	m.ambiguous = true
	if Consume(m, l, d, c, policy, now) == nil {
		t.Fatal("ambiguous consumption authorized")
	}
	m.ambiguous = false
	if !errors.Is(Consume(m, l, d, c, policy, now), ErrConsumed) {
		t.Fatal("ambiguous consume replayed")
	}
	bad := l
	bad.CertificateHash = strings.Repeat("9", 64)
	if _, e := ReadReports(m, bad); e == nil {
		t.Fatal("identity changed")
	}
	m.values["reports.json"] = []byte(`{}`)
	if _, e := ReadReports(m, l); e == nil {
		t.Fatal("malformed accepted")
	}
}
func TestExclusiveConsumptionAllowsOneReaderAcrossContenders(t *testing.T) {
	m, l, c, d, now := fixture(t)
	policy, _ := windowseventrequest.Authorize(d, c, l, now)
	var exclusive sync.Mutex
	var wg sync.WaitGroup
	reads := 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exclusive.Lock()
			defer exclusive.Unlock()
			if Consume(m, l, d, c, policy, now) == nil {
				reads++
			}
		}()
	}
	wg.Wait()
	if reads != 1 || m.writes != 1 {
		t.Fatal("concurrent consumption repeated", reads, m.writes)
	}
}
