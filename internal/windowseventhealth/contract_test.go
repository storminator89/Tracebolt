package windowseventhealth

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsevents"
	"strings"
	"testing"
	"time"
)

func fixture() windowsevents.Report {
	at := time.Date(2026, 10, 7, 20, 0, 0, 0, time.UTC)
	r := windowsevents.Report{Source: windowsevents.Source, Quality: "observed", CollectedAt: at, LimitPerChannel: MaxRows, Complete: true, Channels: []windowsevents.ChannelReport{}}
	for _, name := range []string{"Application", "System"} {
		r.Channels = append(r.Channels, windowsevents.ChannelReport{Channel: name, Source: windowsevents.Source, Quality: "observed", Complete: true, Events: []windowsevents.Event{{RecordID: ^uint64(0), EventID: 65535, Level: 255, Provider: "Invented", Timestamp: at.Add(-time.Minute), Channel: name}}})
	}
	return r
}
func TestHeadersRoundTripAndBounds(t *testing.T) {
	r := fixture()
	s, e := FromReport(r, "sample_"+strings.Repeat("1", 32), strings.Repeat("2", 32))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(s)
	if _, e = Decode(b); e != nil {
		t.Fatal(e)
	}
	if s.Channels[0].Rows[0].RecordID != "18446744073709551615" {
		t.Fatal("record ID rounded")
	}
	for i := range r.Channels {
		r.Channels[i].Events = nil
		for n := 0; n < MaxRows; n++ {
			r.Channels[i].Events = append(r.Channels[i].Events, windowsevents.Event{RecordID: uint64(n + 1), Provider: strings.Repeat("界", 256), Timestamp: r.CollectedAt, Channel: r.Channels[i].Channel})
		}
	}
	s, e = FromReport(r, "sample_"+strings.Repeat("1", 32), strings.Repeat("2", 32))
	if e != nil {
		t.Fatal(e)
	}
	b, _ = json.Marshal(s)
	if len(b) > MaxBytes || s.Channels[0].Complete || !s.Channels[0].Truncated || s.Channels[0].ObservedCount != MaxRows || len(r.Channels[0].Events) != MaxRows {
		t.Fatal("byte trimming changed capture/counts/source")
	}
}
func TestStrictHeaderContractRejectsContentAndQualityLies(t *testing.T) {
	s, e := FromReport(fixture(), "sample_"+strings.Repeat("1", 32), strings.Repeat("2", 32))
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*Snapshot){"security": func(s *Snapshot) { s.Channels[0].Channel = "Security" }, "healthy": func(s *Snapshot) { s.Channels[0].Quality = "healthy" }, "unknown-zero": func(s *Snapshot) { s.Channels[0].Quality = "unavailable"; s.Channels[0].Rows = []Event{} }, "duplicate": func(s *Snapshot) {
		s.Channels[0].Rows = append(s.Channels[0].Rows, s.Channels[0].Rows[0])
		s.Channels[0].ObservedCount = 2
	}, "unknown-reason": func(s *Snapshot) { s.Channels[0].Reason = "private OS error" }, "count-lie": func(s *Snapshot) { s.Channels[0].ObservedCount = 2 }, "long-provider": func(s *Snapshot) { s.Channels[0].Rows[0].Provider = strings.Repeat("a", 257) },
		"bad-provider": func(s *Snapshot) { s.Channels[0].Rows[0].Provider = "private\n" }, "bad-grant": func(s *Snapshot) { s.GrantID = "" }} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(s)
			var copy Snapshot
			json.Unmarshal(b, &copy)
			mutate(&copy)
			if Validate(copy) == nil {
				t.Fatal("invalid snapshot admitted")
			}
		})
	}
	b, _ := json.Marshal(s)
	for _, bad := range [][]byte{append([]byte(" "), b...), []byte(strings.Replace(string(b), `"eventId":65535`, `"eventId":65535,"message":"private"`, 1)), []byte(strings.Replace(string(b), `"level":255`, `"level":255,"level":1`, 1)), []byte(strings.Replace(string(b), `"level":255`, `"level":2.0`, 1))} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical or expanded contract accepted")
		}
	}
}
func TestDeniedPartialAndEmptyRemainHonest(t *testing.T) {
	r := fixture()
	r.Channels[0].Events = []windowsevents.Event{}
	r.Channels[0].Quality = "unavailable"
	r.Channels[0].Complete = false
	r.Channels[0].Reason = windowsevents.ErrAccessDenied.Error()
	r.Complete = false
	r.Quality = "partial"
	s, e := FromReport(r, "sample_"+strings.Repeat("1", 32), strings.Repeat("2", 32))
	if e != nil || s.Channels[0].Quality != "denied" {
		t.Fatal("denial converted to zero", e)
	}
	r = fixture()
	for i := range r.Channels {
		r.Channels[i].Events = []windowsevents.Event{}
	}
	s, e = FromReport(r, "sample_"+strings.Repeat("1", 32), strings.Repeat("2", 32))
	if e != nil || s.Channels[0].Quality != "observed" {
		t.Fatal("empty query should be observed, never healthy", e)
	}
}
func TestConsentExactBoundAndNoImplicitCollection(t *testing.T) {
	binding := strings.Repeat("a", 64)
	c := Consent{ConsentVersion, Scope, binding, strings.Repeat("b", 32), true}
	b, e := EncodeConsent(c, binding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeConsent(b, strings.Repeat("c", 64)); e == nil {
		t.Fatal("foreign binding admitted")
	}
	c.Enabled = false
	if _, e = Collect(context.Background(), "sample_"+strings.Repeat("1", 32), c, binding); e == nil {
		t.Fatal("disabled consent collected")
	}
	c.Enabled = true
	c.Scope = "windows-inventory-v1"
	if _, e = EncodeConsent(c, binding); e == nil {
		t.Fatal("inventory consent became event consent")
	}
}

func TestInvalidOrCanceledCollectionNeverReachesSource(t *testing.T) {
	binding := strings.Repeat("a", 64)
	c := Consent{ConsentVersion, Scope, binding, strings.Repeat("b", 32), true}
	calls := 0
	read := func(context.Context, []string, int) (windowsevents.Report, error) { calls++; return fixture(), nil }
	if _, e := collectUsing(context.Background(), "bad", c, binding, read); e == nil || calls != 0 {
		t.Fatal("invalid generation read source")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := collectUsing(ctx, "sample_"+strings.Repeat("1", 32), c, binding, read); e == nil || calls != 0 {
		t.Fatal("canceled collection read source")
	}
}
