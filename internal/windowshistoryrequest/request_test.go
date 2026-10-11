package windowshistoryrequest

import (
	"bytes"
	"encoding/json"
	history "localrmm/internal/windowseventhistory"
	"strings"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 10, 10, 12, 0, 0, 123456700, time.UTC)

func fixtureConsent() Consent {
	return Consent{SchemaVersion: ConsentVersion, Scope: Scope, SenderBinding: strings.Repeat("c", 64), GrantID: strings.Repeat("d", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
}
func fixtureLocal() LocalContext {
	c := fixtureConsent()
	return LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: "agent_" + strings.Repeat("e", 32), CertificateHash: strings.Repeat("f", 64)}
}
func fixtureRecord(t *testing.T) Record {
	t.Helper()
	c := fixtureConsent()
	l := fixtureLocal()
	r, e := NewSearch(l.DeviceID, l.CertificateHash, 1, c.GrantID, history.Search{Channel: "Application", Start: fixtureTime.Add(-24 * time.Hour), End: fixtureTime.Add(-time.Hour)}, fixtureTime)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func fixtureClaim(t *testing.T) Record {
	t.Helper()
	r := fixtureRecord(t)
	r, e := Claim(r, r.Description.Identity, fixtureConsent(), fixtureLocal(), fixtureTime.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func fixtureReport(r Record) history.Report {
	return history.Report{Source: history.Source, Warning: history.PrivacyWarning, Quality: history.QualityObserved, Complete: true, CollectedAt: fixtureTime.Add(2 * time.Second), Search: history.CloneSearch(r.Description.Query.Search), Events: []history.Result{{Event: history.Event{RecordID: ^uint64(0), EventID: 42, Level: 2, Provider: "Synthetic fixture", Timestamp: fixtureTime.Add(-2 * time.Hour), Channel: "Application"}, Quality: history.QualityObserved, Complete: true}}}
}
func fixtureAccepted(t *testing.T) (Record, history.Report) {
	t.Helper()
	r := fixtureClaim(t)
	report := fixtureReport(r)
	r, e := Accept(r, r.Description.Identity, fixtureConsent(), fixtureLocal(), report, fixtureTime.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	return r, report
}
func TestConsentPurposeAndAcknowledgements(t *testing.T) {
	c := fixtureConsent()
	for _, mutate := range []func(*Consent){func(c *Consent) { c.HistoryAcknowledged = false }, func(c *Consent) { c.ContentAcknowledged = false }, func(c *Consent) { c.Scope = "windows-selected-application-system-event-content-v1" }, func(c *Consent) { c.SchemaVersion = "tracebolt.windows-event-content-consent.v1" }, func(c *Consent) { c.HTTPPlaintextAcknowledged = true }, func(c *Consent) { c.GrantID = "" }} {
		bad := c
		mutate(&bad)
		if ValidateConsent(bad, c.SenderBinding, c.Profile) == nil {
			t.Fatal("old or incomplete grant accepted")
		}
	}
	c.Profile = "http-test"
	if ValidateConsent(c, c.SenderBinding, c.Profile) == nil {
		t.Fatal("plaintext warning not required")
	}
	c.HTTPPlaintextAcknowledged = true
	if ValidateConsent(c, c.SenderBinding, c.Profile) != nil {
		t.Fatal("explicit plaintext scope rejected")
	}
}
func TestOriginalBoundsAndConsumeOnce(t *testing.T) {
	r := fixtureRecord(t)
	raw, e := Encode(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(raw, '\n'), bytes.Replace(raw, []byte(`"schemaVersion":`), []byte(`"unknown":0,"schemaVersion":`), 1)} {
		if _, e = Decode(bad); e == nil {
			t.Fatal("noncanonical record accepted")
		}
	}
	r = fixtureClaim(t)
	if _, e = Claim(r, r.Description.Identity, fixtureConsent(), fixtureLocal(), fixtureTime.Add(2*time.Second)); e != ErrConsumed {
		t.Fatal("claim replay permitted")
	}
	bad := r.Description
	bad.Query.Search = history.CloneSearch(bad.Query.Search)
	bad.Query.Search.End = fixtureTime.Add(time.Second)
	bad.Identity.QueryDigest, _ = queryDigest(bad)
	if ValidateDescription(bad) == nil {
		t.Fatal("future query admitted")
	}
	if _, e = Authorize(r.Description, fixtureConsent(), fixtureLocal(), r.Description.ExpiresAt); e != ErrExpired {
		t.Fatal("original expiry refreshed")
	}
}
func TestMessagesRequireExactAcceptedReceiptAndPreserveExpiry(t *testing.T) {
	r, report := fixtureAccepted(t)
	l := fixtureLocal()
	c := fixtureConsent()
	selections := []Selection{{"Application", "18446744073709551615"}}
	m, e := NewMessages(l.DeviceID, l.CertificateHash, 2, c.GrantID, r, report, selections, fixtureTime.Add(10*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if m.Description.CreatedAt != r.Description.CreatedAt || m.Description.ExpiresAt != r.Description.ExpiresAt || m.Description.HeaderCollectedAt != r.Description.HeaderCollectedAt || m.Description.HeaderGenerationID != r.Description.HeaderGenerationID || m.Description.SearchReceipt == nil || *m.Description.SearchReceipt != *r.Receipt || m.Description.Query.Search != nil || m.Description.Query.Events[0].RecordID != ^uint64(0) || ValidateAgainstSearch(m.Description, r, report) != nil {
		t.Fatal("search receipt or expiry not preserved")
	}
	raw, e := Encode(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = Claim(m, m.Description.Identity, c, l, r.Receipt.AcceptedAt.Add(-time.Nanosecond)); e == nil {
		t.Fatal("message claim predates accepted search")
	}
	if _, e = Claim(m, m.Description.Identity, c, l, r.Description.ExpiresAt); e != ErrExpired {
		t.Fatal("message followup refreshed expiry")
	}
	if _, e = NewMessages(l.DeviceID, l.CertificateHash, 2, c.GrantID, r, report, selections, r.Description.ExpiresAt); e == nil {
		t.Fatal("expired report promoted")
	}
	for _, mutate := range []func(*history.Report){func(r *history.Report) { r.Events[0].Event.Provider = "Substituted" }, func(r *history.Report) { r.CollectedAt = r.CollectedAt.Add(time.Second) }, func(r *history.Report) { r.Events = nil }, func(r *history.Report) { r.Search = nil }} {
		bad := report
		bad.Events = append([]history.Result{}, report.Events...)
		mutate(&bad)
		if _, e = NewMessages(l.DeviceID, l.CertificateHash, 2, c.GrantID, r, bad, selections, fixtureTime.Add(time.Minute)); e == nil {
			t.Fatal("changed or lost search promoted")
		}
	}
	for _, s := range [][]Selection{nil, {{"Application", "018446744073709551615"}}, {{"System", "18446744073709551615"}}, {{"Application", "18446744073709551615"}, {"Application", "18446744073709551615"}}} {
		if _, e = NewMessages(l.DeviceID, l.CertificateHash, 2, c.GrantID, r, report, s, fixtureTime.Add(time.Minute)); e == nil {
			t.Fatal("invalid exact selection admitted")
		}
	}
	bad := m.Description
	receipt := *bad.SearchReceipt
	receipt.ResultDigest = "sha256:" + strings.Repeat("a", 64)
	bad.SearchReceipt = &receipt
	bad.Identity.QueryDigest, _ = queryDigest(bad)
	if ValidateAgainstSearch(bad, r, report) == nil {
		t.Fatal("forged source receipt accepted")
	}
}
func TestMessageFollowupAcceptsOnlyExactRows(t *testing.T) {
	r, search := fixtureAccepted(t)
	c := fixtureConsent()
	l := fixtureLocal()
	m, e := NewMessages(l.DeviceID, l.CertificateHash, 2, c.GrantID, r, search, []Selection{{"Application", "18446744073709551615"}}, fixtureTime.Add(4*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	m, e = Claim(m, m.Description.Identity, c, l, fixtureTime.Add(5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	wrongPolicy := m
	wrongPolicy.PolicyDigest = "sha256:" + strings.Repeat("0", 64)
	if Validate(wrongPolicy) == nil {
		t.Fatal("message claim policy differs from original accepted search")
	}
	report := history.Report{Source: history.Source, Warning: history.PrivacyWarning, Quality: history.QualityObserved, Complete: true, CollectedAt: fixtureTime.Add(6 * time.Second), Events: []history.Result{{Event: m.Description.Query.Events[0], Message: "synthetic-only-content", Quality: history.QualityObserved, Complete: true}}}
	accepted, e := Accept(m, m.Description.Identity, c, l, report, fixtureTime.Add(7*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(accepted)
	if bytes.Contains(raw, []byte("synthetic-only-content")) {
		t.Fatal("durable record contains message")
	}
	report.Events[0].Event.Provider = "Changed"
	if _, e = Accept(m, m.Description.Identity, c, l, report, fixtureTime.Add(7*time.Second)); e == nil {
		t.Fatal("substituted selected metadata accepted")
	}
}
