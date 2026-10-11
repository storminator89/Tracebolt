package windowshistorywire

import (
	"bytes"
	"context"
	"encoding/json"
	history "localrmm/internal/windowseventhistory"
	oldwire "localrmm/internal/windowseventwire"
	request "localrmm/internal/windowshistoryrequest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func historyFixture(t *testing.T, n int) (request.Record, request.Consent, request.LocalContext, Result) {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 123456700, time.UTC)
	c := request.Consent{SchemaVersion: request.ConsentVersion, Scope: request.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	l := request.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: "agent_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64)}
	r, e := request.NewSearch(l.DeviceID, l.CertificateHash, 1, c.GrantID, history.Search{Channel: "Application", Start: now.Add(-24 * time.Hour), End: now.Add(-time.Hour)}, now)
	if e != nil {
		t.Fatal(e)
	}
	r, e = request.Claim(r, r.Description.Identity, c, l, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	claim, e := ClaimFor(r.Description, r.PolicyDigest)
	if e != nil {
		t.Fatal(e)
	}
	report := history.Report{Source: history.Source, Warning: history.PrivacyWarning, Quality: history.QualityObserved, CollectedAt: now.Add(2 * time.Second), Complete: true, Search: history.CloneSearch(r.Description.Query.Search), Events: make([]history.Result, n)}
	for i := range report.Events {
		report.Events[i] = history.Result{Event: history.Event{RecordID: ^uint64(0) - uint64(i), EventID: 42, Level: 2, Provider: "Synthetic publisher", Timestamp: now.Add(-2 * time.Hour), Channel: "Application"}, Quality: history.QualityObserved, Complete: true}
	}
	return r, c, l, Result{claim, report}
}
func TestSearchWireRoundTripEmptyAndHundredHeaders(t *testing.T) {
	for _, count := range []int{0, 1, 100} {
		r, _, _, result := historyFixture(t, count)
		raw, e := EncodeDescription(r.Description)
		if e != nil {
			t.Fatal(e)
		}
		d, e := DecodeDescription(raw)
		if e != nil || !reflect.DeepEqual(d, r.Description) {
			t.Fatal("search description changed")
		}
		body, e := EncodeResult(result)
		if e != nil {
			t.Fatal(e)
		}
		got, e := DecodeResult(body)
		if e != nil || !reflect.DeepEqual(got, result) || ValidateResultForGrant(got, Grant{r.Description, r.PolicyDigest, *r.ClaimedAt}) != nil {
			t.Fatal("search wire changed")
		}
		if count > 0 && (!bytes.Contains(body, []byte(`"recordId":"18446744073709551615"`)) || !bytes.Contains(body, []byte(".1234567Z"))) {
			t.Fatal("uint64 or timestamp precision lost")
		}
		direct, e := json.Marshal(result)
		if e != nil || !bytes.Equal(direct, body) {
			t.Fatal("direct serializer leaked numeric IDs")
		}
		for _, bad := range [][]byte{append(append([]byte{}, body...), '\n'), bytes.Replace(body, []byte(`"source":`), []byte(`"unknown":0,"source":`), 1), bytes.Replace(body, []byte(`"search":`), []byte(`"search":null,"search":`), 1)} {
			if _, e = DecodeResult(bad); e == nil {
				t.Fatal("noncanonical result accepted")
			}
		}
	}
}
func TestMessagesWireBindsOriginalSearchReceipt(t *testing.T) {
	r, c, l, result := historyFixture(t, 1)
	accepted, e := request.Accept(r, r.Description.Identity, c, l, result.Report, r.Description.CreatedAt.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	m, e := request.NewMessages(l.DeviceID, l.CertificateHash, 2, c.GrantID, accepted, result.Report, []request.Selection{{Channel: "Application", RecordID: strconv.FormatUint(result.Report.Events[0].Event.RecordID, 10)}}, r.Description.CreatedAt.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	body, e := EncodeDescription(m.Description)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeDescription(body)
	if e != nil || !reflect.DeepEqual(got, m.Description) || request.ValidateAgainstSearch(got, accepted, result.Report) != nil {
		t.Fatal("message receipt roundtrip failed")
	}
	dto, _ := DescriptionForBrowser(m.Description)
	dto.SearchReceipt.ResultDigest = "sha256:" + strings.Repeat("f", 64)
	if _, e = dto.Native(); e == nil {
		t.Fatal("modified receipt digest accepted")
	}
	if m.Description.SearchReceipt.ResultDigest != accepted.Receipt.ResultDigest {
		t.Fatal("DTO aliased original receipt")
	}
}
func TestOldEventContentProofCannotPromoteToHistory(t *testing.T) {
	pair := wirePair(t)
	old, e := oldwire.NewSignedRequest(context.Background(), "http://manager.test", oldwire.PeekPath, pair, 1, time.Now().UTC(), []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	for _, keys := range [][2]string{{oldwire.CertificateHeader, CertificateHeader}, {oldwire.SequenceHeader, SequenceHeader}, {oldwire.SignedAtHeader, SignedAtHeader}, {oldwire.SignatureHeader, SignatureHeader}} {
		old.Header.Set(keys[1], old.Header.Get(keys[0]))
		old.Header.Del(keys[0])
	}
	old.URL.Path = PeekPath
	v, e := New(Config{Origin: "http://manager.test", Registry: &publicFixture{}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.Verify(old); e == nil {
		t.Fatal("old content proof authorized broader history")
	}
}
func TestSearchWireNoMessageSmuggling(t *testing.T) {
	r, _, _, result := historyFixture(t, 1)
	result.Report.Events[0].Message = "secret"
	if ValidateResult(result, r.Description) == nil {
		t.Fatal("search message smuggling accepted")
	}
	if _, e := EncodeResult(result); e == nil {
		t.Fatal("search message smuggling serialized")
	}
	_, _, _, empty := historyFixture(t, 0)
	empty.Report.Search = nil
	if _, e := EncodeResult(empty); e == nil {
		t.Fatal("empty selected-message result accepted")
	}
}
