package windowshardware

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func requestFixture() Request {
	b := strings.Repeat("a", 64)
	return Request{Consent: Consent{ConsentVersion, Scope, b, strings.Repeat("b", 32), true}, SenderBinding: b, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}
func TestPowerSentinelsAndNonchargingMidrange(t *testing.T) {
	for _, tc := range []struct {
		ac, flags, percent          uint8
		seconds                     uint32
		presence, charging, quality string
		wantPercent, wantTime       bool
	}{{0, 0, 50, 3600, "present", "no", "observed", true, true}, {1, 8, 99, 42, "present", "yes", "observed", true, false}, {1, 128, 0, 0, "absent", "unknown", "observed", false, false}, {255, 255, 255, 0xffffffff, "unknown", "unknown", "partial", false, false}, {0, 0, 255, 0xffffffff, "present", "no", "partial", false, false}, {1, 255, 50, 100, "unknown", "unknown", "partial", false, false}, {0, 128 | 8, 10, 50, "unknown", "unknown", "partial", false, false}, {0, 0, 101, 0, "present", "no", "partial", false, true}} {
		p := powerStatus(tc.ac, tc.flags, tc.percent, tc.seconds)
		if !validPower(p) || p.BatteryPresence != tc.presence || p.Charging != tc.charging || p.Quality != tc.quality || (p.BatteryPercent != nil) != tc.wantPercent || (p.EstimatedSeconds != nil) != tc.wantTime {
			t.Fatalf("power: %+v -> %+v", tc, p)
		}
	}
}
func TestModelCanonicalBoundsAndSources(t *testing.T) {
	s := Empty(requestFixture(), ErrUnavailable.Error())
	s.Power = powerStatus(1, 128, 255, 0xffffffff)
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"source":"Win32_BIOS"`), []byte(`"source":"system-serial"`), 1), bytes.Replace(raw, []byte(`"chassis":`), []byte(`"uuid":"private","chassis":`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical/unknown metadata accepted")
		}
	}
	for _, v := range []string{"20260230000000.000000+000", "2026**********.******+***", "20260101000000.000000:000", "20260101000060.000000+000"} {
		if validDMTF(v) {
			t.Fatal("guessed malformed/unknown DMTF", v)
		}
	}
	if !validDMTF("20260228091530.000000+060") {
		t.Fatal("valid DMTF")
	}
	s.Firmware.SerialNumber = observedField(strings.Repeat("a", 65), nil, 64)
	s.Firmware.Quality = "partial"
	s.Firmware.Reason = ErrPartial.Error()
	if s.Firmware.SerialNumber.Value != nil || Validate(s) != nil {
		t.Fatal("serial bound")
	}
	s.Power.EstimatedSeconds = new(uint32)
	if Validate(s) == nil {
		t.Fatal("AC estimate invented")
	}
	_ = json.Valid(raw)
}
func TestConsentAndIndependentSourceFailures(t *testing.T) {
	r := requestFixture()
	calls := 0
	source := func(context.Context) (System, error) { calls++; return System{}, ErrDenied }
	r.Consent.Enabled = false
	if _, e := CollectWithSources(context.Background(), r, source, nil, nil, nil); e != ErrDisabled || calls != 0 {
		t.Fatal("disabled source opened")
	}
	r.Consent.Enabled = true
	s, e := CollectWithSources(context.Background(), r, source, nil, func(context.Context) (Power, error) { return powerStatus(1, 128, 255, 0xffffffff), nil }, nil)
	if e != nil || s.System.Quality != "denied" || s.Power.BatteryPresence != "absent" {
		t.Fatal("failure erased independent source")
	}
	r.Consent.Scope = "windows-session-context-v1"
	if _, e := CollectWithSources(context.Background(), r, source, nil, nil, nil); e == nil || calls != 1 {
		t.Fatal("old scope gained serial")
	}
}
