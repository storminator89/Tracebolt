package macosinventorywire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanstore"
	"localrmm/internal/macosinventory"
	"localrmm/internal/signedhttp"
)

func fixtureControl() Control {
	return Control{ControlVersion, Binding{Platform, Profile, "agent_" + strings.Repeat("a", 32), strings.Repeat("b", 64)}, strings.Repeat("c", 32), 1, 1, true, 0, time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
}
func fixtureSnapshot(t *testing.T, c Control, sequence uint64, at time.Time) macosinventory.Snapshot {
	t.Helper()
	id, err := GenerationID(c.Binding, c.GrantID, c.GrantRevision, sequence)
	if err != nil {
		t.Fatal(err)
	}
	status := func(source string) macosinventory.Status {
		return macosinventory.Status{Source: source, Quality: "observed"}
	}
	return macosinventory.Snapshot{
		SchemaVersion: macosinventory.SchemaVersion, Scope: macosinventory.Scope, GrantID: c.GrantID, GenerationID: id, CollectedAt: at,
		Hardware:  macosinventory.Hardware{Status: status(macosinventory.HardwareSource), ModelIdentifier: "Mac14,2", PhysicalCPUs: 8, LogicalCPUs: 8, MemoryCapacityBytes: 1 << 34},
		Receipts:  macosinventory.Receipts{Status: status(macosinventory.ReceiptSource), Identifiers: []string{"org.example.app"}},
		Processes: macosinventory.Processes{Status: status(macosinventory.ProcessSource), Rows: []macosinventory.Process{{PID: 1, ParentPID: 0, AccountingName: "launchd", NameQuality: "observed"}}},
		Network: macosinventory.Network{
			IPv4: macosinventory.Interfaces{Status: status(macosinventory.IPv4Source), Rows: []macosinventory.Interface{{Name: "en0", MTU: 1500, Up: true, Running: true, Addresses: []macosinventory.Address{{IP: "192.0.2.1", PrefixBits: 24}}}}},
			IPv6: macosinventory.Interfaces{Status: status(macosinventory.IPv6Source), Rows: []macosinventory.Interface{{Name: "en0", MTU: 1500, Up: true, Running: true, Addresses: []macosinventory.Address{}}}},
		},
	}
}
func fixtureReport(t *testing.T, sequence uint64, at time.Time) Report {
	t.Helper()
	c := fixtureControl()
	r, err := BuildReport(c, sequence, fixtureSnapshot(t, c, sequence, at))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func reportBytes(t *testing.T, r Report) []byte {
	t.Helper()
	raw, err := EncodeReport(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func controlBytes(t *testing.T, c Control) []byte {
	t.Helper()
	raw, err := EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func disabled(t *testing.T, floor uint64) Control {
	t.Helper()
	c := fixtureControl()
	out, err := Disable(c, floor, c.ChangedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCanonicalRoundTripsAndEmbeddedObject(t *testing.T) {
	c := fixtureControl()
	r := fixtureReport(t, 1, c.ChangedAt)
	raw := reportBytes(t, r)
	got, err := DecodeReport(raw)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("report round trip", err)
	}
	snapshotRaw, _ := macosinventory.Encode(r.Snapshot)
	if !bytes.Contains(raw, append([]byte(`"snapshot":`), snapshotRaw...)) || bytes.Contains(raw, []byte(`"snapshot":"`)) {
		t.Fatal("snapshot is not the exact canonical JSON object")
	}
	if MaxSnapshotBytes != macosinventory.MaxBytes || MaxReportBytes != 520*1024 || MaxReportBytes-MaxSnapshotBytes != 8*1024 {
		t.Fatal("independent byte budgets changed")
	}
	for _, control := range []Control{c, disabled(t, 17)} {
		b := controlBytes(t, control)
		got, err := DecodeControl(b)
		if err != nil || got != control {
			t.Fatal("control round trip", err)
		}
	}
	for _, request := range [][]byte{raw, controlBytes(t, c), controlBytes(t, disabled(t, 17))} {
		receipt, err := ReceiptFor(request, c.ChangedAt.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := EncodeReceipt(receipt, request)
		if err != nil || len(b) > MaxReceiptBytes {
			t.Fatal(err)
		}
		got, err := DecodeReceipt(b, request)
		if err != nil || !reflect.DeepEqual(got, receipt) {
			t.Fatal("receipt round trip", err)
		}
	}
}
func mutations(raw []byte) map[string][]byte {
	return map[string][]byte{
		"leading space":       append([]byte(" "), raw...),
		"trailing newline":    append(bytes.Clone(raw), '\n'),
		"second document":     append(bytes.Clone(raw), []byte(`{}`)...),
		"duplicate top-level": bytes.Replace(raw, []byte(`"schemaVersion":`), []byte(`"schemaVersion":"forged","schemaVersion":`), 1),
		"duplicate identical": bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":1,"grantRevision":1`), 1),
		"duplicate nested":    bytes.Replace(raw, []byte(`"platform":"darwin"`), []byte(`"platform":"darwin","platform":"darwin"`), 1),
		"unknown top-level":   bytes.Replace(raw, []byte(`"schemaVersion":`), []byte(`"privateMarker":"never-echo","schemaVersion":`), 1),
		"unknown nested":      bytes.Replace(raw, []byte(`"platform":"darwin"`), []byte(`"platform":"darwin","unknown":true`), 1),
		"wrong case":          bytes.Replace(raw, []byte(`"grantRevision":`), []byte(`"GrantRevision":`), 1),
		"numeric exponent":    bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":1e0`), 1),
		"numeric fraction":    bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":1.0`), 1),
		"overflow":            bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":18446744073709551616`), 1),
		"negative":            bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":-1`), 1),
		"escaped key":         bytes.Replace(raw, []byte(`"grantId":`), []byte(`"grant\u0049d":`), 1),
		"escaped value":       bytes.Replace(raw, []byte(`"darwin"`), []byte(`"d\u0061rwin"`), 1),
		"noncanonical time":   bytes.Replace(raw, []byte(`00Z"`), []byte(`00.000Z"`), 1),
		"invalid utf8":        append(bytes.Clone(raw[:len(raw)-1]), 0xff, '}'),
		"null":                []byte(`null`), "array": []byte(`[]`), "empty": nil,
	}
}
func TestStrictCanonicalReportControlAndReceipt(t *testing.T) {
	c := fixtureControl()
	raw := reportBytes(t, fixtureReport(t, 1, c.ChangedAt))
	control := controlBytes(t, c)
	receipt, _ := ReceiptFor(raw, c.ChangedAt)
	receiptRaw, _ := EncodeReceipt(receipt, raw)
	for kind, original := range map[string][]byte{"report": raw, "control": control, "receipt": receiptRaw} {
		for name, bad := range mutations(original) {
			t.Run(kind+"/"+name, func(t *testing.T) {
				var err error
				switch kind {
				case "report":
					_, err = DecodeReport(bad)
				case "control":
					_, err = DecodeControl(bad)
				case "receipt":
					_, err = DecodeReceipt(bad, raw)
				}
				if err == nil {
					t.Fatal("accepted noncanonical bytes")
				}
				if strings.Contains(err.Error(), "never-echo") {
					t.Fatal("private data in error")
				}
			})
		}
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"modelIdentifier":"Mac14,2"`), []byte(`"modelIdentifier":"Mac14,2","modelIdentifier":"Mac14,2"`), 1),
		bytes.Replace(raw, []byte(`"modelIdentifier":`), []byte(`"serial":"never-echo","modelIdentifier":`), 1),
		bytes.Replace(raw, []byte(`"addresses":[]`), []byte(`"addresses":null`), 1),
	} {
		if _, err := DecodeReport(bad); err == nil {
			t.Fatal("nested snapshot ambiguity accepted")
		}
	}
	if _, err := DecodeReport(control); err == nil {
		t.Fatal("control became report")
	}
	if _, err := DecodeControl(raw); err == nil {
		t.Fatal("report became control")
	}
}
func TestReportBindingsCannotBeRewritten(t *testing.T) {
	c := fixtureControl()
	mutators := map[string]func(*Report){
		"schema":              func(r *Report) { r.SchemaVersion = macosinventory.SchemaVersion },
		"platform":            func(r *Report) { r.Binding.Platform = "macos" },
		"basic profile":       func(r *Report) { r.Binding.Profile = "basic-readonly-v1" },
		"linux profile":       func(r *Report) { r.Binding.Profile = "linux-read-admin-v1" },
		"windows profile":     func(r *Report) { r.Binding.Profile = "windows-read-admin-v1" },
		"sender":              func(r *Report) { r.Binding.SenderBinding = strings.Repeat("d", 64) },
		"device":              func(r *Report) { r.Binding.DeviceID = "agent_" + strings.Repeat("e", 32) },
		"grant":               func(r *Report) { r.GrantID = strings.Repeat("d", 32) },
		"grant revision":      func(r *Report) { r.GrantRevision++ },
		"control revision":    func(r *Report) { r.ControlRevision++ },
		"sequence":            func(r *Report) { r.CaptureSequence++ },
		"generation":          func(r *Report) { r.GenerationID = "sample_" + strings.Repeat("d", 32) },
		"time":                func(r *Report) { r.CollectedAt = r.CollectedAt.Add(time.Second) },
		"lifetime":            func(r *Report) { r.ExpiresAt = r.ExpiresAt.Add(time.Nanosecond) },
		"digest":              func(r *Report) { r.SnapshotSHA256 = strings.Repeat("e", 64) },
		"source quality":      func(r *Report) { r.SourceQuality = "unknown" },
		"snapshot grant":      func(r *Report) { r.Snapshot.GrantID = strings.Repeat("d", 32) },
		"snapshot generation": func(r *Report) { r.Snapshot.GenerationID = "sample_" + strings.Repeat("d", 32) },
		"snapshot time":       func(r *Report) { r.Snapshot.CollectedAt = r.Snapshot.CollectedAt.Add(time.Second) },
		"snapshot data":       func(r *Report) { r.Snapshot.Hardware.ModelIdentifier = "Mac15,2" },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			r := fixtureReport(t, 1, c.ChangedAt)
			mutate(&r)
			if _, err := EncodeReport(r); err == nil {
				t.Fatal("altered binding accepted")
			}
		})
	}
	r := fixtureReport(t, 1, c.ChangedAt)
	for _, mutate := range []func(*Control){func(v *Control) { v.Binding.SenderBinding = strings.Repeat("d", 64) }, func(v *Control) { v.GrantID = strings.Repeat("d", 32) }, func(v *Control) { v.ChangedAt = v.ChangedAt.Add(time.Nanosecond) }} {
		other := c
		mutate(&other)
		if ValidateReportBinding(r, other) == nil {
			t.Fatal("foreign current control accepted")
		}
	}
	if ValidateReportBinding(r, disabled(t, 1)) != ErrDisabled {
		t.Fatal("disabled control admitted report")
	}
	if _, err := BuildReport(c, 2, r.Snapshot); err == nil {
		t.Fatal("builder rewrote capture binding")
	}
	if _, err := BuildReport(disabled(t, 1), 1, r.Snapshot); err != ErrDisabled {
		t.Fatal("builder ignored disable", err)
	}
}
func TestQualityAndOriginalAge(t *testing.T) {
	c := fixtureControl()
	for _, name := range []string{"full", "partial", "field partial", "unknown"} {
		s := fixtureSnapshot(t, c, 1, c.ChangedAt)
		want := name
		switch name {
		case "partial":
			s.Network.IPv6 = macosinventory.EmptyInterfaces(macosinventory.IPv6Source, macosinventory.ErrDenied.Error())
		case "field partial":
			s.Processes.Rows[0].AccountingName = ""
			s.Processes.Rows[0].NameQuality = "unavailable"
			want = "partial"
		case "unknown":
			s = macosinventory.Empty(macosinventory.Request{Consent: macosinventory.Consent{GrantID: c.GrantID}, GenerationID: s.GenerationID, CollectedAt: s.CollectedAt}, macosinventory.ErrUnavailable.Error())
		}
		r, err := BuildReport(c, 1, s)
		if err != nil || r.SourceQuality != want {
			t.Fatal(name, err, r.SourceQuality)
		}
		before := reportBytes(t, r)
		for _, tc := range []struct {
			age  time.Duration
			want string
		}{{0, "fresh"}, {time.Minute - time.Nanosecond, "fresh"}, {time.Minute, "stale"}, {Retention - time.Nanosecond, "stale"}, {Retention, "expired"}} {
			q, err := Assess(r, s.CollectedAt.Add(tc.age))
			if err != nil || q.SourceQuality != want || q.Freshness != tc.want || q.Age != tc.age {
				t.Fatal(name, tc, q, err)
			}
		}
		if _, err := Assess(r, r.CollectedAt.Add(-time.Nanosecond)); err == nil {
			t.Fatal("future capture accepted")
		}
		if ValidateLifetime(r, r.ExpiresAt) != ErrExpired {
			t.Fatal("expiry boundary extended")
		}
		if !bytes.Equal(before, reportBytes(t, r)) || !reflect.DeepEqual(r.Snapshot, s) {
			t.Fatal("assessment rewrote original evidence")
		}
	}
}

func largeSnapshot(t *testing.T, size int) macosinventory.Snapshot {
	t.Helper()
	c := fixtureControl()
	s := fixtureSnapshot(t, c, 1, c.ChangedAt)
	s.Receipts.Identifiers = make([]string, macosinventory.MaxReceipts)
	for i := range s.Receipts.Identifiers {
		s.Receipts.Identifiers[i] = fmt.Sprintf("r%04d", i)
	}
	raw, _ := json.Marshal(s)
	remaining := size - len(raw)
	for i := range s.Receipts.Identifiers {
		n := min(256-len(s.Receipts.Identifiers[i]), remaining)
		s.Receipts.Identifiers[i] += strings.Repeat("x", n)
		remaining -= n
	}
	if remaining != 0 {
		t.Fatal("fixture size cannot fit", remaining)
	}
	raw, _ = json.Marshal(s)
	if len(raw) != size {
		t.Fatal("wrong fixture bytes")
	}
	return s
}
func TestIndependentBoundsAndOldTelemetryRoutes(t *testing.T) {
	c := fixtureControl()
	s := largeSnapshot(t, MaxSnapshotBytes)
	r, err := BuildReport(c, 1, s)
	if err != nil {
		t.Fatal("maximum snapshot rejected", err)
	}
	raw := reportBytes(t, r)
	if len(raw) <= MaxSnapshotBytes || len(raw) > MaxReportBytes {
		t.Fatal("report envelope budget incorrect")
	}
	if _, err := DecodeReport(raw); err != nil {
		t.Fatal("maximum canonical report", err)
	}
	if _, err := BuildReport(c, 1, largeSnapshot(t, MaxSnapshotBytes+1)); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
	if _, err := DecodeReport(bytes.Repeat([]byte(" "), MaxReportBytes+1)); err != ErrBounds {
		t.Fatal("report ceiling not enforced first", err)
	}
	if _, err := DecodeControl(bytes.Repeat([]byte(" "), MaxControlBytes+1)); err != ErrBounds {
		t.Fatal("control ceiling", err)
	}
	if _, err := DecodeReceipt(bytes.Repeat([]byte(" "), MaxReceiptBytes+1), raw); err != ErrBounds {
		t.Fatal("receipt ceiling", err)
	}
	if lanstore.MaxFrameBytes != 72*1024 || signedhttp.MaxBodyBytes != 72*1024 {
		t.Fatal("old 72 KiB budgets widened")
	}
	if _, err := lanstore.ValidateFrame(raw, c.ChangedAt); err == nil {
		t.Fatal("large inventory report admitted to old telemetry")
	}
	if _, err := lanstore.ValidateFrame(reportBytes(t, fixtureReport(t, 1, c.ChangedAt)), c.ChangedAt); err == nil {
		t.Fatal("small inventory report admitted to old telemetry")
	}
}
func TestOverflowAndUnrepresentableDates(t *testing.T) {
	c := fixtureControl()
	for _, sequence := range []uint64{0, MaxSequence + 1, math.MaxUint64} {
		if _, err := GenerationID(c.Binding, c.GrantID, 1, sequence); err == nil {
			t.Fatal("overflow accepted", sequence)
		}
	}
	r := fixtureReport(t, MaxSequence, c.ChangedAt)
	if ValidateReport(r) != nil {
		t.Fatal("last safe sequence rejected")
	}
	if _, err := Assess(r, time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)); err != ErrInvalid {
		t.Fatal("duration overflow fabricated age", err)
	}
	for _, bad := range []uint64{0, 2, MaxSequence + 1, math.MaxUint64} {
		other := c
		other.GrantRevision = bad
		if ValidateControl(other) == nil {
			t.Fatal("grant revision accepted", bad)
		}
	}
	if _, err := Disable(c, math.MaxUint64, c.ChangedAt); err == nil {
		t.Fatal("disable floor overflow")
	}
	for _, at := range []time.Time{time.Time{}, time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), c.ChangedAt.In(time.FixedZone("offset", 3600))} {
		s := fixtureSnapshot(t, c, 1, at)
		if _, err := BuildReport(c, 1, s); err == nil {
			t.Fatal("bad timestamp accepted", at)
		}
	}
}
func TestReceiptExactRequestBindingAndPrivacy(t *testing.T) {
	c := fixtureControl()
	r := fixtureReport(t, 1, c.ChangedAt)
	raw := reportBytes(t, r)
	receipt, err := ReceiptFor(raw, c.ChangedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Receipt){
		"binding":         func(r *Receipt) { r.Binding.SenderBinding = strings.Repeat("d", 64) },
		"sequence":        func(r *Receipt) { r.CaptureFloor++ },
		"generation":      func(r *Receipt) { r.GenerationID = "sample_" + strings.Repeat("d", 32) },
		"grant":           func(r *Receipt) { r.GrantID = strings.Repeat("d", 32) },
		"request hash":    func(r *Receipt) { r.RequestSHA256 = strings.Repeat("d", 64) },
		"snapshot hash":   func(r *Receipt) { r.SnapshotSHA256 = strings.Repeat("d", 64) },
		"capture age":     func(r *Receipt) { at := r.CollectedAt.Add(time.Second); r.CollectedAt = &at },
		"status":          func(r *Receipt) { r.Status = "disabled" },
		"kind":            func(r *Receipt) { r.Kind = "control" },
		"missing capture": func(r *Receipt) { r.CollectedAt = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := receipt
			mutate(&bad)
			if _, err := EncodeReceipt(bad, raw); err == nil {
				t.Fatal("foreign receipt accepted")
			}
		})
	}
	changed := r
	changed.Snapshot.Hardware.ModelIdentifier = "Mac15,2"
	changed.SnapshotSHA256, _ = SnapshotDigest(changed.Snapshot)
	if ValidateReceipt(receipt, reportBytes(t, changed)) == nil {
		t.Fatal("same-sequence altered request accepted")
	}
	if _, err := ReceiptFor(raw, r.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatal("receipt refreshed expired capture", err)
	}
	bad := bytes.Replace(raw, []byte(`"modelIdentifier":"Mac14,2"`), []byte(`"modelIdentifier":"/private/never-echo-secret"`), 1)
	_, err = DecodeReport(bad)
	if err == nil || err.Error() != ErrInvalid.Error() {
		t.Fatal("unbounded/private diagnostic", err)
	}
	// Decoding a historical receipt does not regenerate or refresh ReceivedAt.
	encoded, _ := EncodeReceipt(receipt, raw)
	got, err := DecodeReceipt(encoded, raw)
	if err != nil || !got.ReceivedAt.Equal(receipt.ReceivedAt) || !got.CollectedAt.Equal(r.CollectedAt) {
		t.Fatal("receipt lost original times", err)
	}
}

func TestReceiptRejectsUnboundedInputsBeforeEncoding(t *testing.T) {
	c := fixtureControl()
	raw := reportBytes(t, fixtureReport(t, 1, c.ChangedAt))
	if _, err := ReceiptFor(bytes.Repeat([]byte("x"), MaxReportBytes+1), c.ChangedAt); err != ErrBounds {
		t.Fatal("oversized receipt request", err)
	}
	receipt, err := ReceiptFor(raw, c.ChangedAt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Status = strings.Repeat("private", MaxReceiptBytes)
	if _, err := EncodeReceipt(receipt, raw); err != ErrInvalid {
		t.Fatal("unbounded receipt field", err)
	}
	receipt, err = ReceiptFor(raw, c.ChangedAt)
	if err != nil {
		t.Fatal(err)
	}
	at := receipt.CollectedAt.In(time.FixedZone("offset", 3600))
	receipt.CollectedAt = &at
	if _, err := EncodeReceipt(receipt, raw); err != ErrInvalid {
		t.Fatal("noncanonical receipt capture timezone", err)
	}
}
