package windowseventrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
)

var fixtureTime = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func fixtureHeaders() windowseventhealth.Snapshot {
	return windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("a", 32), GenerationID: "sample_" + strings.Repeat("b", 32), CollectedAt: fixtureTime.Add(-time.Minute), Channels: []windowseventhealth.Channel{
		{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 14, Level: 2, Provider: "Synthetic fixture", Timestamp: fixtureTime.Add(-2 * time.Minute)}}},
		{Channel: "System", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "42", EventID: 21, Level: 3, Provider: "Synthetic fixture", Timestamp: fixtureTime.Add(-3 * time.Minute)}}},
	}}
}
func fixtureConsent() Consent {
	return Consent{ConsentVersion, Scope, strings.Repeat("c", 64), strings.Repeat("d", 32), "tls", true, true, false}
}
func fixtureLocal() LocalContext {
	c := fixtureConsent()
	return LocalContext{c.SenderBinding, c.Profile, "agent_" + strings.Repeat("e", 32), strings.Repeat("f", 64)}
}
func fixtureRecord(t *testing.T) Record {
	t.Helper()
	c := fixtureConsent()
	r, e := New("agent_"+strings.Repeat("e", 32), strings.Repeat("f", 64), 1, c.GrantID, fixtureHeaders(), []Selection{{"Application", "18446744073709551615"}, {"System", "42"}}, fixtureTime)
	if e != nil {
		t.Fatal("fixture request rejected")
	}
	return r
}
func fixtureClaim(t *testing.T) Record {
	t.Helper()
	r := fixtureRecord(t)
	c := fixtureConsent()
	out, e := Claim(r, r.Description.Identity, c, fixtureLocal(), fixtureTime.Add(time.Second))
	if e != nil {
		t.Fatal("fixture claim rejected")
	}
	return out
}
func fixtureReport(r Record) windowseventcontent.Report {
	x := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: windowseventcontent.QualityObserved, CollectedAt: fixtureTime.Add(2 * time.Second), Complete: true, Events: []windowseventcontent.Result{}}
	for _, event := range r.Description.Query.Events {
		x.Events = append(x.Events, windowseventcontent.Result{Event: event, Message: "synthetic-only-content-marker", Quality: windowseventcontent.QualityObserved, Complete: true})
	}
	return x
}
func TestConsentIsSeparateExplicitAndDestinationBound(t *testing.T) {
	c := fixtureConsent()
	raw, e := EncodeConsent(c, c.SenderBinding, c.Profile)
	if e != nil {
		t.Fatal("valid scope rejected")
	}
	if _, e = DecodeConsent(raw, c.SenderBinding, c.Profile); e != nil {
		t.Fatal("round trip rejected")
	}
	mutations := []func(*Consent){func(v *Consent) { v.SchemaVersion = windowseventhealth.ConsentVersion }, func(v *Consent) { v.Scope = windowseventhealth.Scope }, func(v *Consent) { v.SenderBinding = strings.Repeat("0", 64) }, func(v *Consent) { v.GrantID = "" }, func(v *Consent) { v.ContentAcknowledged = false }, func(v *Consent) { v.HTTPPlaintextAcknowledged = true }, func(v *Consent) { v.Profile = "http-test" }}
	for i, mutate := range mutations {
		v := c
		mutate(&v)
		if ValidateConsent(v, c.SenderBinding, c.Profile) == nil {
			t.Fatalf("invalid consent %d accepted", i)
		}
	}
	c.Profile = "http-test"
	c.HTTPPlaintextAcknowledged = true
	if ValidateConsent(c, c.SenderBinding, "http-test") != nil {
		t.Fatal("explicit HTTP content consent rejected")
	}
	c.HTTPPlaintextAcknowledged = false
	if ValidateConsent(c, c.SenderBinding, "http-test") == nil {
		t.Fatal("HTTP without content warning accepted")
	}
}
func TestSelectedHeadersAreExactAndBounded(t *testing.T) {
	h := fixtureHeaders()
	r := fixtureRecord(t)
	if ValidateAgainstHeaders(r.Description, h) != nil {
		t.Fatal("matching headers rejected")
	}
	if r.Description.Query.Events[0].RecordID != ^uint64(0) {
		t.Fatal("full-width record ID lost")
	}
	for _, selections := range [][]Selection{nil, {{"Security", "42"}}, {{"System", "042"}}, {{"System", "7"}}, {{"System", "42"}, {"System", "42"}}} {
		if _, e := QueryFromHeaders(h, selections); e == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	many := make([]Selection, 17)
	if _, e := QueryFromHeaders(h, many); e == nil {
		t.Fatal("selection budget widened")
	}
	h.Channels[0].Rows[0].Provider = "Other fixture"
	if ValidateAgainstHeaders(r.Description, h) == nil {
		t.Fatal("changed sample accepted")
	}
	for _, age := range []time.Duration{time.Minute, -MaxHeaderAge} {
		h = fixtureHeaders()
		h.CollectedAt = fixtureTime.Add(age)
		if _, e := New(r.Description.DeviceID, r.Description.CertificateHash, 1, r.Description.GrantID, h, []Selection{{"System", "42"}}, fixtureTime); e == nil {
			t.Fatal("future or expired sample accepted")
		}
	}
}
func TestImmutableRequestDigestAndFixedBudgets(t *testing.T) {
	r := fixtureRecord(t)
	cases := []func(*Description){func(v *Description) { v.Budgets.MaxSelectedEvents++ }, func(v *Description) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }, func(v *Description) { v.GrantID = strings.Repeat("0", 32) }, func(v *Description) { v.DeviceID = "agent_" + strings.Repeat("0", 32) }, func(v *Description) { v.CertificateHash = strings.Repeat("0", 64) }, func(v *Description) { v.HeaderGenerationID = "sample_" + strings.Repeat("0", 32) }, func(v *Description) { v.HeaderCollectedAt = v.HeaderCollectedAt.Add(-time.Second) }, func(v *Description) { v.CreatedAt = v.CreatedAt.Add(time.Second) }}
	for i, change := range cases {
		v := r.Description
		change(&v)
		if ValidateDescription(v) == nil {
			t.Fatalf("modified query %d accepted", i)
		}
	}
	if FixedBudgets() != (Budgets{windowseventcontent.MaxSelectedEvents, windowseventcontent.MaxMessageBytes, windowseventcontent.MaxTotalMessageBytes, int64(windowseventcontent.CollectionTimeout / time.Millisecond)}) {
		t.Fatal("source v1 budgets changed without request protocol review")
	}
}
func TestClaimOnceAndFreshConsentRecheck(t *testing.T) {
	r := fixtureRecord(t)
	c := fixtureConsent()
	at := fixtureTime.Add(time.Second)
	wrong := r.Description.Identity
	wrong.Sequence++
	if _, e := Claim(r, wrong, c, fixtureLocal(), at); !errors.Is(e, ErrConflict) {
		t.Fatal("wrong identity claim accepted")
	}
	claimed, e := Claim(r, r.Description.Identity, c, fixtureLocal(), at)
	if e != nil {
		t.Fatal("claim rejected")
	}
	if _, e = Claim(claimed, claimed.Description.Identity, c, fixtureLocal(), at); !errors.Is(e, ErrConsumed) {
		t.Fatal("repeated claim accepted")
	}
	if r.State != Pending || r.ClaimedAt != nil {
		t.Fatal("input record mutated")
	}
	for _, change := range []func(*Consent){func(v *Consent) { v.Enabled = false }, func(v *Consent) { v.GrantID = strings.Repeat("0", 32) }} {
		other := c
		change(&other)
		if _, e := Authorize(claimed.Description, other, fixtureLocal(), at); !errors.Is(e, ErrDisabled) {
			t.Fatal("disabled or replaced grant accepted")
		}
	}
	if _, e := Authorize(claimed.Description, c, LocalContext{strings.Repeat("0", 64), c.Profile, fixtureLocal().DeviceID, fixtureLocal().CertificateHash}, at); e == nil {
		t.Fatal("foreign binding accepted")
	}
	if _, e := Authorize(claimed.Description, c, fixtureLocal(), claimed.Description.ExpiresAt); !errors.Is(e, ErrExpired) {
		t.Fatal("expiry revived")
	}
}
func TestResultAcceptanceContainsOnlyDigestAndOriginalExpiry(t *testing.T) {
	r := fixtureClaim(t)
	c := fixtureConsent()
	report := fixtureReport(r)
	at := fixtureTime.Add(3 * time.Second)
	accepted, e := Accept(r, r.Description.Identity, c, fixtureLocal(), report, at)
	if e != nil {
		t.Fatal("valid result rejected")
	}
	raw, e := Encode(accepted)
	if e != nil || bytes.Contains(raw, []byte("synthetic-only-content-marker")) || bytes.Contains(raw, []byte(`"message"`)) {
		t.Fatal("content entered authority metadata")
	}
	if accepted.Receipt.ExpiresAt != r.Description.ExpiresAt {
		t.Fatal("acceptance renewed expiry")
	}
	if _, e = Accept(accepted, r.Description.Identity, c, fixtureLocal(), report, at); !errors.Is(e, ErrConsumed) {
		t.Fatal("accepted result recollected")
	}
	for _, captured := range []time.Time{fixtureTime, at.Add(time.Second)} {
		v := report
		v.CollectedAt = captured
		if _, e = Accept(r, r.Description.Identity, c, fixtureLocal(), v, at); e == nil {
			t.Fatal("unbound capture time accepted")
		}
	}
	changed := c
	changed.Enabled = false
	if _, e = Accept(r, r.Description.Identity, changed, fixtureLocal(), report, at); !errors.Is(e, ErrDisabled) {
		t.Fatal("disabled result released")
	}
	report.Events[0].Event.Provider = "Other fixture"
	if _, e = Accept(r, r.Description.Identity, c, fixtureLocal(), report, at); e == nil {
		t.Fatal("different selected event accepted")
	}
}
func TestCancellationExpiryAndClockRollbackCannotReopen(t *testing.T) {
	r := fixtureClaim(t)
	c := fixtureConsent()
	id := r.Description.Identity
	canceled, e := Cancel(r, id, fixtureTime.Add(2*time.Second))
	if e != nil {
		t.Fatal("cancel rejected")
	}
	if _, e = Claim(canceled, id, c, fixtureLocal(), fixtureTime.Add(3*time.Second)); !errors.Is(e, ErrCanceled) {
		t.Fatal("canceled request reopened")
	}
	expired, e := Expire(canceled, r.Description.ExpiresAt)
	if e != nil {
		t.Fatal("expiry rejected")
	}
	if _, e = Claim(expired, id, c, fixtureLocal(), r.Description.ExpiresAt.Add(time.Second)); !errors.Is(e, ErrExpired) {
		t.Fatal("expired request reopened")
	}
	if CheckTime(expired, fixtureTime.Add(time.Second)) == nil {
		t.Fatal("backwards clock revived expired request")
	}
	if _, e = Expire(r, r.Description.ExpiresAt.Add(-time.Nanosecond)); e == nil {
		t.Fatal("early expiry accepted")
	}
	if _, e = Cancel(r, id, fixtureTime); e == nil {
		t.Fatal("cancel backdated before claim")
	}
	again, e := Expire(expired, r.Description.ExpiresAt.Add(time.Minute))
	if e != nil || *again.ExpiredAt != *expired.ExpiredAt {
		t.Fatal("repeat expiry changed original terminal time")
	}
}
func TestStrictMetadataDecodingAndStateInvariants(t *testing.T) {
	r := fixtureClaim(t)
	raw, e := Encode(r)
	if e != nil {
		t.Fatal("encoding failed")
	}
	out, e := Decode(raw)
	if e != nil || out.Description.Identity != r.Description.Identity {
		t.Fatal("canonical round trip failed")
	}
	variants := [][]byte{append([]byte(" "), raw...), append(append([]byte(nil), raw...), []byte(" {}")...), bytes.Replace(raw, []byte(`"state":"claimed"`), []byte(`"state":"claimed","state":"claimed"`), 1), bytes.Replace(raw, []byte(`"state":"claimed"`), []byte(`"State":"claimed"`), 1), bytes.Replace(raw, []byte(`"state":"claimed"`), []byte(`"state":"claimed","message":"private"`), 1)}
	for i, v := range variants {
		if _, e := Decode(v); e == nil {
			t.Fatalf("noncanonical input %d accepted", i)
		}
	}
	bad := r
	bad.State = Pending
	if Validate(bad) == nil {
		t.Fatal("claimed metadata labeled pending")
	}
	bad = r
	bad.PolicyDigest = ""
	if Validate(bad) == nil {
		t.Fatal("claim without policy digest")
	}
	at := r.Description.ExpiresAt
	bad = r
	bad.CanceledAt = &at
	bad.State = Canceled
	if Validate(bad) == nil {
		t.Fatal("cancel at expiry accepted")
	}
	encodedConsent, _ := json.Marshal(windowseventhealth.Consent{SchemaVersion: windowseventhealth.ConsentVersion, Scope: windowseventhealth.Scope, SenderBinding: fixtureConsent().SenderBinding, GrantID: fixtureConsent().GrantID, Enabled: true})
	if _, e := DecodeConsent(encodedConsent, fixtureConsent().SenderBinding, "tls"); e == nil {
		t.Fatal("event-header grant promoted to content")
	}
}

func TestForeignDeviceAndCertificateCannotUseLocalConsent(t *testing.T) {
	c := fixtureConsent()
	r := fixtureRecord(t)
	for _, local := range []LocalContext{
		{c.SenderBinding, c.Profile, "agent_" + strings.Repeat("0", 32), r.Description.CertificateHash},
		{c.SenderBinding, c.Profile, r.Description.DeviceID, strings.Repeat("0", 64)},
		{c.SenderBinding, "http-test", r.Description.DeviceID, r.Description.CertificateHash},
	} {
		if _, e := Authorize(r.Description, c, local, fixtureTime.Add(time.Second)); e == nil {
			t.Fatal("foreign local identity accepted")
		}
	}
}
