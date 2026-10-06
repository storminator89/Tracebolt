package enrollmentstate

import (
	"bytes"
	"context"
	"testing"
)

func roundTripLedger(t *testing.T, e *Engine) *Engine {
	t.Helper()
	raw, err := e.EncodeTrustedLedger()
	if err != nil {
		t.Fatal(err)
	}
	clone, err := RestoreTrustedLedger(e.config, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := clone.EncodeTrustedLedger()
	if err != nil || !bytes.Equal(raw, raw2) {
		t.Fatal("private ledger did not round trip")
	}
	return clone
}
func TestTrustedLedgerRestoresEveryPhaseAndTombstone(t *testing.T) {
	e := engine(t)
	f := newClaimFixture(t, 1)
	s := f.create(t, e)
	e = roundTripLedger(t, e)
	var err error
	s, err = e.Claim(context.Background(), f.command(s, testNow+1), f.proof(t, testNow+1))
	if err != nil {
		t.Fatal(err)
	}
	e = roundTripLedger(t, e)
	s, err = e.Approve(context.Background(), ApproveCommand{Control: control(s, 102), DeviceID: id("agent", 1), KeyFingerprint: s.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	roundTripLedger(t, e)
	e, f, ca, s, i := flowIntent(t)
	e = roundTripLedger(t, e)
	cert := ca.issue(t, i, s.UpdatedAt+1)
	s, err = e.CommitIssued(context.Background(), control(s, 104), cert)
	if err != nil {
		t.Fatal(err)
	}
	e = roundTripLedger(t, e)
	c := control(s, 105)
	s, err = e.Activate(context.Background(), c, activationProof(t, f, cert, c.RequestID, c.Now))
	if err != nil {
		t.Fatal(err)
	}
	e = roundTripLedger(t, e)
	s, err = e.Terminate(context.Background(), TerminalCommand{Control: control(s, 106), State: Revoked})
	if err != nil {
		t.Fatal(err)
	}
	roundTripLedger(t, e)
	for _, terminalState := range []State{Canceled, Rejected, Expired} {
		e = engine(t)
		f = newClaimFixture(t, 1)
		s = f.create(t, e)
		s, err = e.Claim(context.Background(), f.command(s, testNow+1), f.proof(t, testNow+1))
		if err != nil {
			t.Fatal(err)
		}
		c = control(s, 199)
		if terminalState == Expired {
			c.Now = s.DeadlineAt
		}
		if _, err = e.Terminate(context.Background(), TerminalCommand{Control: c, State: terminalState}); err != nil {
			t.Fatal(err)
		}
		roundTripLedger(t, e)
	}
}
func TestTrustedLedgerRejectsPartialBindingAndPrivateCorruption(t *testing.T) {
	e, f, _, _, _ := flowIntent(t)
	raw, _ := e.EncodeTrustedLedger()
	for _, n := range []int{0, 1, 38, len(raw) / 2, len(raw) - 1} {
		if _, err := RestoreTrustedLedger(e.config, raw[:n]); err == nil {
			t.Fatal("accepted partial private ledger")
		}
	}
	if _, err := RestoreTrustedLedger(e.config, append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("accepted trailing private data")
	}
	wrong := e.config
	wrong.Binding.Origin = "https://other.example"
	if _, err := RestoreTrustedLedger(wrong, raw); err == nil {
		t.Fatal("accepted rebound ledger")
	}
	rec := e.records[f.challenge.InvitationID]
	rec.publicKeyDERBase64 = ""
	e.records[f.challenge.InvitationID] = rec
	raw, _ = e.EncodeTrustedLedger()
	if _, err := RestoreTrustedLedger(e.config, raw); err == nil {
		t.Fatal("accepted missing persisted approved key")
	}
}
func TestTrustedLedgerRejectsCrossRecordPrivateVerifierReuse(t *testing.T) {
	e := engine(t)
	f := newClaimFixture(t, 1)
	f.create(t, e)
	g := newClaimFixture(t, 2)
	g.create(t, e)
	r := e.records[g.challenge.InvitationID]
	r.verifier = e.records[f.challenge.InvitationID].verifier
	e.records[g.challenge.InvitationID] = r
	raw, _ := e.EncodeTrustedLedger()
	if _, err := RestoreTrustedLedger(e.config, raw); err == nil {
		t.Fatal("accepted duplicate verifier")
	}
}

func TestTrustedLedgerConfigExactValidatedRead(t *testing.T) {
	e, _, _, _, _ := flowIntent(t)
	raw, err := e.EncodeTrustedLedger()
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(raw)
	config, err := TrustedLedgerConfig(raw)
	if err != nil || config != e.config || !bytes.Equal(raw, before) {
		t.Fatal("exact config inspection", err)
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0)} {
		if _, err := TrustedLedgerConfig(bad); err == nil {
			t.Fatal("config accepted incomplete or trailing ledger")
		}
	}
	changed := bytes.Replace(raw, []byte(`"InvitationTTL":600`), []byte(`"InvitationTTL":601`), 1)
	if bytes.Equal(changed, raw) {
		t.Fatal("fixture header not found")
	}
	if _, err := TrustedLedgerConfig(changed); err == nil {
		t.Fatal("config returned without validating the ledger against it")
	}
}
