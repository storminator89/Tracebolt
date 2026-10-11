package windowseventwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
)

func fixture(t testing.TB, ids ...uint64) (windowseventrequest.Record, windowseventrequest.Consent, windowseventrequest.LocalContext, Result) {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 123456700, time.UTC)
	c := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
	local := windowseventrequest.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: "agent_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64)}
	if len(ids) == 0 {
		ids = []uint64{math.MaxUint64}
	}
	h := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("e", 32), GenerationID: "sample_" + strings.Repeat("f", 32), CollectedAt: now.Add(-time.Minute), Channels: []windowseventhealth.Channel{
		{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: uint32(len(ids)), Rows: make([]windowseventhealth.Event, len(ids))},
		{Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}},
	}}
	selections := make([]windowseventrequest.Selection, len(ids))
	for i, id := range ids {
		text := strconv.FormatUint(id, 10)
		h.Channels[0].Rows[i] = windowseventhealth.Event{RecordID: text, EventID: uint16(42 + i), Level: 2, Provider: "Synthetic publisher", Timestamp: now.Add(-2 * time.Minute)}
		selections[i] = windowseventrequest.Selection{Channel: "Application", RecordID: text}
	}
	r, e := windowseventrequest.New(local.DeviceID, local.CertificateHash, math.MaxUint64, c.GrantID, h, selections, now)
	if e != nil {
		t.Fatal(e)
	}
	r, e = windowseventrequest.Claim(r, r.Description.Identity, c, local, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	claim, e := ClaimFor(r.Description, r.PolicyDigest)
	if e != nil {
		t.Fatal(e)
	}
	report := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: windowseventcontent.QualityObserved, CollectedAt: now.Add(2 * time.Second), Complete: true, Events: make([]windowseventcontent.Result, len(ids))}
	for i, event := range r.Description.Query.Events {
		report.Events[i] = windowseventcontent.Result{Event: event, Message: "Synthetic harmless message", Quality: windowseventcontent.QualityObserved, Complete: true}
	}
	return r, c, local, Result{claim, report}
}

func TestAllUint64ValuesAndNativePrecisionRoundTrip(t *testing.T) {
	for _, id := range []uint64{1, math.MaxInt32, math.MaxUint32, 1<<53 - 1, 1 << 53, 1<<53 + 1, math.MaxInt64, math.MaxUint64} {
		t.Run(strconv.FormatUint(id, 10), func(t *testing.T) {
			r, _, _, result := fixture(t, id)
			d, e := EncodeDescription(r.Description)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Contains(d, []byte(`"recordId":"`+strconv.FormatUint(id, 10)+`"`)) || bytes.Contains(d, []byte("record_id")) || !bytes.Contains(d, []byte(`"sequence":"18446744073709551615"`)) {
				t.Fatal("unsafe identifier serialization")
			}
			if !bytes.Contains(d, []byte(".1234567Z")) {
				t.Fatal("100ns precision lost")
			}
			native, e := DecodeDescription(d)
			if e != nil || !reflect.DeepEqual(native, r.Description) {
				t.Fatal("description did not round trip")
			}
			raw, e := EncodeResult(result)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := DecodeResult(raw)
			if e != nil || !reflect.DeepEqual(decoded, result) {
				t.Fatal("result did not round trip")
			}
			direct, e := json.Marshal(result)
			if e != nil || !bytes.Equal(raw, direct) {
				t.Fatal("public result marshaler bypass")
			}
			var indirect Result
			if json.Unmarshal(raw, &indirect) != nil || !reflect.DeepEqual(indirect, result) {
				t.Fatal("public result unmarshaler bypass")
			}
			grant, e := GrantFor(r)
			if e != nil {
				t.Fatal(e)
			}
			gb, e := json.Marshal(grant)
			if e != nil || bytes.Contains(gb, []byte("record_id")) {
				t.Fatal("public grant unsafe")
			}
			var gd Grant
			if json.Unmarshal(gb, &gd) != nil || !reflect.DeepEqual(gd, grant) {
				t.Fatal("public grant roundtrip")
			}
			status := Status{Record: r, LocalStatus: "checking", ContentStatus: "unavailable"}
			sb, e := json.Marshal(status)
			if e != nil || bytes.Contains(sb, []byte("record_id")) {
				t.Fatal("public status unsafe")
			}
			var sd Status
			if json.Unmarshal(sb, &sd) != nil || !reflect.DeepEqual(sd, status) {
				t.Fatal("public status roundtrip")
			}
		})
	}
}
func TestCanonicalEnvelopesRejectAmbiguity(t *testing.T) {
	r, c, local, result := fixture(t)
	cap, e := CapabilityFor(c, local, math.MaxUint64, r.Description.CreatedAt)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := GrantFor(r)
	capRaw, _ := EncodeCapability(cap)
	claimRaw, _ := EncodeClaim(result.Claim)
	resultRaw, _ := EncodeResult(result)
	grantRaw, _ := EncodeGrant(g)
	descRaw, _ := EncodeDescription(r.Description)
	statusRaw, _ := EncodeStatus(StatusInput{Claim: result.Claim, LocalStatus: "checking"})
	statusOut, _ := EncodeStatusResponse(Status{Record: r, ContentStatus: "unavailable"})
	tests := []struct {
		name   string
		raw    []byte
		decode func([]byte) error
	}{
		{"capability", capRaw, func(b []byte) error { _, e := DecodeCapability(b); return e }},
		{"claim", claimRaw, func(b []byte) error { _, e := DecodeClaim(b); return e }},
		{"result", resultRaw, func(b []byte) error { _, e := DecodeResult(b); return e }},
		{"grant", grantRaw, func(b []byte) error { _, e := DecodeGrant(b); return e }},
		{"description", descRaw, func(b []byte) error { _, e := DecodeDescription(b); return e }},
		{"status input", statusRaw, func(b []byte) error { _, e := DecodeStatusInput(b); return e }},
		{"status output", statusOut, func(b []byte) error { _, e := DecodeStatus(b); return e }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if e := tc.decode(tc.raw); e != nil {
				t.Fatal(e)
			}
			bad := [][]byte{nil, []byte("null"), []byte("{}"), append(bytes.Clone(tc.raw), '\n'), append(bytes.Clone(tc.raw), []byte("{}")...), append([]byte(" "), tc.raw...), bytes.Replace(tc.raw, []byte(`"sequence":"18446744073709551615"`), []byte(`"sequence":18446744073709551615`), 1), bytes.Replace(tc.raw, []byte(`"sequence":"18446744073709551615"`), []byte(`"sequence":"018446744073709551615"`), 1), bytes.Replace(tc.raw, []byte(`"sequence":"18446744073709551615"`), []byte(`"sequence":"18446744073709551615","sequence":"18446744073709551615"`), 1), bytes.Replace(tc.raw, []byte(`"sequence":`), []byte(`"Sequence":`), 1), bytes.Replace(tc.raw, []byte(`"sequence":"18446744073709551615"`), []byte(`"sequence":null`), 1), append([]byte(`{"unsupported":true,`), tc.raw[1:]...), bytes.Repeat([]byte(" "), MaxBodyBytes+1)}
			for i, b := range bad {
				if e := tc.decode(b); e == nil {
					t.Fatalf("ambiguity accepted %d", i)
				}
			}
		})
	}
	// DTO field spellings/number forms are independently strict.
	for _, bad := range [][]byte{
		bytes.Replace(resultRaw, []byte(`"recordId":"18446744073709551615"`), []byte(`"recordId":18446744073709551615`), 1),
		bytes.Replace(resultRaw, []byte(`"recordId":"18446744073709551615"`), []byte(`"recordId":"018446744073709551615"`), 1),
		bytes.Replace(resultRaw, []byte(`"recordId":"18446744073709551615"`), []byte(`"record_id":"18446744073709551615"`), 1),
		bytes.Replace(resultRaw, []byte(`"recordId":"18446744073709551615"`), []byte(`"recordId":"18446744073709551615","recordId":"18446744073709551615"`), 1),
		bytes.Replace(resultRaw, []byte(`"eventId":42`), []byte(`"eventId":4.2e1`), 1),
		bytes.Replace(resultRaw, []byte(`.1234567Z`), []byte(`.123456700Z`), 1),
		bytes.Replace(resultRaw, []byte(`"message":`), []byte(`"Message":`), 1),
	} {
		if _, e := DecodeResult(bad); e == nil {
			t.Fatal("ambiguous event DTO accepted")
		}
	}
}
func TestCapabilityOriginalAgeAndPolicyBinding(t *testing.T) {
	r, c, local, _ := fixture(t)
	cap, e := CapabilityFor(c, local, 1, r.Description.CreatedAt)
	if e != nil {
		t.Fatal(e)
	}
	if CapabilityFresh(cap, cap.CollectedAt) != nil || CapabilityFresh(cap, cap.CollectedAt.Add(CapabilityMaxAge-time.Nanosecond)) != nil {
		t.Fatal("fresh rejected")
	}
	for _, now := range []time.Time{cap.CollectedAt.Add(-time.Nanosecond), cap.CollectedAt.Add(CapabilityMaxAge), cap.CollectedAt.Add(time.Hour)} {
		if CapabilityFresh(cap, now) == nil {
			t.Fatal("stale/future accepted")
		}
	}
	cap.Consent.Enabled = false
	if ValidateCapability(cap) == nil {
		t.Fatal("changed policy accepted")
	}
	cap, e = CapabilityFor(cap.Consent, local, 2, cap.CollectedAt)
	if e != nil || cap.Consent.Enabled {
		t.Fatal("disabled report not preserved")
	}
	if CapabilityFresh(cap, cap.CollectedAt) != nil {
		t.Fatal("disabled metadata should remain reportable")
	}
	cap.Sequence = 0
	if ValidateCapability(cap) == nil {
		t.Fatal("zero sequence accepted")
	}
	local.Profile = "http-test"
	if _, e := CapabilityFor(c, local, 1, r.Description.CreatedAt); e == nil {
		t.Fatal("mismatched transport accepted")
	}
}
func TestResultExactBindingsAndOriginalExpiry(t *testing.T) {
	r, _, _, result := fixture(t, math.MaxUint64, 1<<53+1)
	grant, _ := GrantFor(r)
	if ValidateResultForGrant(result, grant) != nil {
		t.Fatal("valid result rejected")
	}
	for _, tc := range []struct {
		name   string
		change func(*Result)
	}{
		{"request ID", func(v *Result) { v.Claim.Identity.ID = "winevent_" + strings.Repeat("1", 32) }},
		{"sequence", func(v *Result) { v.Claim.Identity.Sequence-- }},
		{"query digest", func(v *Result) { v.Claim.Identity.QueryDigest = "sha256:" + strings.Repeat("1", 64) }},
		{"policy", func(v *Result) { v.Claim.PolicyDigest = "sha256:" + strings.Repeat("2", 64) }},
		{"device", func(v *Result) { v.Claim.DeviceID = "agent_" + strings.Repeat("1", 32) }},
		{"certificate", func(v *Result) { v.Claim.CertificateHash = strings.Repeat("1", 64) }},
		{"grant", func(v *Result) { v.Claim.GrantID = strings.Repeat("1", 32) }},
		{"expiry", func(v *Result) { v.Claim.ExpiresAt = v.Claim.ExpiresAt.Add(time.Second) }},
		{"record", func(v *Result) { v.Report.Events[0].Event.RecordID-- }},
		{"channel", func(v *Result) { v.Report.Events[0].Event.Channel = "System" }},
		{"event ID", func(v *Result) { v.Report.Events[0].Event.EventID++ }},
		{"level", func(v *Result) { v.Report.Events[0].Event.Level++ }},
		{"provider", func(v *Result) { v.Report.Events[0].Event.Provider = "Other publisher" }},
		{"timestamp100ns", func(v *Result) {
			v.Report.Events[0].Event.Timestamp = v.Report.Events[0].Event.Timestamp.Add(100 * time.Nanosecond)
		}},
		{"reordered", func(v *Result) { v.Report.Events[0], v.Report.Events[1] = v.Report.Events[1], v.Report.Events[0] }},
		{"before claim", func(v *Result) { v.Report.CollectedAt = grant.ClaimedAt.Add(-time.Nanosecond) }},
		{"at expiry", func(v *Result) { v.Report.CollectedAt = v.Claim.ExpiresAt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := result
			v.Report.Events = append([]windowseventcontent.Result(nil), result.Report.Events...)
			tc.change(&v)
			if ValidateResultForGrant(v, grant) == nil {
				t.Fatal("binding substitution accepted")
			}
		})
	}
}
func TestWorstCaseJSONEscapingHasIndependentEncodedBudget(t *testing.T) {
	r, _, _, result := fixture(t, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, math.MaxUint64)
	result.Report.Quality = windowseventcontent.QualityBounded
	result.Report.Complete = false
	result.Report.Truncated = true
	for i := range result.Report.Events {
		p := &result.Report.Events[i]
		if i < 4 {
			p.Message = strings.Repeat("\x01", windowseventcontent.MaxMessageBytes)
		} else {
			p.Message = ""
			p.Quality = windowseventcontent.QualityBounded
			p.Complete = false
			p.Truncated = true
			p.Reason = windowseventcontent.ErrTotalLimit.Error()
		}
	}
	if ValidateResult(result, r.Description) != nil {
		t.Fatal("64KiB report rejected")
	}
	raw, e := EncodeResult(result)
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) < 6*windowseventcontent.MaxTotalMessageBytes || len(raw) > MaxBodyBytes {
		t.Fatal("escape/body budgets conflated")
	}
	decoded, e := DecodeResult(raw)
	if e != nil || !reflect.DeepEqual(decoded, result) {
		t.Fatal("worst case did not round trip")
	}
	result.Report.Events[0].Message += "x"
	if _, e := EncodeResult(result); e == nil {
		t.Fatal("per-row overrun accepted")
	}
	if _, e := DecodeResult(bytes.Repeat([]byte("x"), MaxBodyBytes+1)); e == nil {
		t.Fatal("encoded cap overrun accepted")
	}
}
func TestPartialNativeReportSurvivesFixedErrorAndReceiptsMatch(t *testing.T) {
	r, c, local, result := fixture(t, 1, 2)
	// Native Read returns (partial report, fixed nonnil error); preserving the
	// valid successful row is intentional and must not depend on err==nil.
	nativeRead := func() (windowseventcontent.Report, error) {
		report := result.Report
		report.Events = append([]windowseventcontent.Result(nil), report.Events...)
		report.Events[1].Message = ""
		report.Events[1].Complete = false
		report.Events[1].Quality = windowseventcontent.QualityUnavailable
		report.Events[1].Reason = windowseventcontent.ErrNotFound.Error()
		report.Quality = windowseventcontent.QualityPartial
		report.Complete = false
		return report, windowseventcontent.ErrNotFound
	}
	report, readErr := nativeRead()
	if readErr == nil {
		t.Fatal("fixture missing fixed failure")
	}
	result.Report = report
	dto, e := ReportForBrowser(report, r.Description.Query)
	if e != nil || dto.Events[0].Message == "" || dto.Events[1].Reason != readErr.Error() {
		t.Fatal("partial result lost")
	}
	b, e := EncodeResult(result)
	if e != nil {
		t.Fatal(e)
	}
	back, e := DecodeResult(b)
	if e != nil || back.Report.Quality != windowseventcontent.QualityPartial {
		t.Fatal("partial result lost in transport")
	}
	accepted, e := windowseventrequest.Accept(r, r.Description.Identity, c, local, report, report.CollectedAt.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	pd, e := ReportDigest(report, r.Description.Query)
	if e != nil || pd != accepted.Receipt.ResultDigest {
		t.Fatal("foundation receipt semantics changed")
	}
	wd, e := ResultDigest(result)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	if wd != "sha256:"+hex.EncodeToString(h[:]) || wd == pd {
		t.Fatal("wire and foundation digest identities conflated")
	}
	receiptBytes, e := EncodeReceipt(*accepted.Receipt)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := DecodeReceipt(receiptBytes)
	if e != nil || receipt != *accepted.Receipt {
		t.Fatal("receipt roundtrip")
	}
}
func TestContentDiagnosticFormattingAlwaysRedacted(t *testing.T) {
	r, _, _, result := fixture(t)
	result.Report.Events[0].Message = "SYNTHETIC_PRIVATE_MARKER"
	report, _ := ReportForBrowser(result.Report, r.Description.Query)
	description, _ := DescriptionForBrowser(r.Description)
	record, _ := RecordForBrowser(r)
	grant, _ := GrantFor(r)
	for _, v := range []any{result, report, report.Events[0], report.Events[0].Event, description, description.Query, record, grant, ResultDTO{result.Claim, report}, GrantDTO{description, grant.PolicyDigest, grant.ClaimedAt}, Status{Record: r, ContentStatus: "unavailable"}, Verified{Body: []byte("SYNTHETIC_PRIVATE_MARKER")}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(verb, v)
			if !strings.Contains(out, "redacted") || strings.Contains(out, "SYNTHETIC_PRIVATE_MARKER") || strings.Contains(out, "Synthetic publisher") {
				t.Fatal("diagnostic content escaped")
			}
		}
	}
}
func FuzzStrictResultDecode(f *testing.F) {
	_, _, _, seed := fixture(f)
	raw, err := EncodeResult(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("{}"))
	f.Add([]byte(`{"claim":null,"report":null}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := DecodeResult(b)
		if e == nil {
			canonical, e := EncodeResult(v)
			if e != nil || !bytes.Equal(b, canonical) {
				t.Fatal("noncanonical successful decode")
			}
		}
	})
}

func FuzzRecordIDExactDecimal(f *testing.F) {
	for _, id := range []uint64{0, 1, 1<<53 - 1, 1 << 53, 1<<53 + 1, math.MaxUint64} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id uint64) {
		dto := EventDTO{RecordID: strconv.FormatUint(id, 10), EventID: 65535, Level: 255, Provider: "Synthetic publisher", Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 123456700, time.UTC), Channel: "System"}
		native, e := dto.Native()
		if id == 0 {
			if e == nil {
				t.Fatal("zero accepted")
			}
			return
		}
		if e != nil || native.RecordID != id || eventDTO(native) != dto {
			t.Fatal("uint64 or timestamp precision loss")
		}
		raw, e := json.Marshal(dto)
		if e != nil {
			t.Fatal(e)
		}
		var back EventDTO
		if decode(raw, 4096, &back) != nil || back != dto {
			t.Fatal("decimal representation did not round trip")
		}
	})
}
