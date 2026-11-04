package windowsprocesswatch

import (
	"encoding/json"
	"localrmm/internal/windowsfullprocesses"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Input, time.Time) {
	t.Helper()
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	name := "worker.exe"
	device := "agent_" + strings.Repeat("1", 32)
	c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: strings.Repeat("2", 64), GrantID: strings.Repeat("3", 32), Revision: 1, Enabled: true, ChangedAt: at}
	messages, e := windowsfullprocesses.Build(device, c, 1, windowsfullprocesses.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullprocesses.Row{{PID: 0, Name: &name, NameQuality: "observed"}}})
	if e != nil {
		t.Fatal(e)
	}
	p := &windowsfullprocesses.Complete{Manifest: *messages[0].Manifest, ManifestSHA256: messages[0].ManifestSHA256, ReceivedAt: at}
	return Input{DeviceID: device, InvitationID: "invite_" + strings.Repeat("4", 32), CertificateHash: strings.Repeat("5", 64), CurrentLeaf: strings.Repeat("5", 64), AuthorityUntil: at.Add(time.Hour), Complete: p, Counts: map[string]int{name: 1}}, at
}
func TestWindowsProcessWatchDefaultConsentAndCanonicalState(t *testing.T) {
	in, at := fixture(t)
	s := New()
	v, e := s.View(in, at)
	if e != nil || v.Status != "disabled" || v.Source != nil || len(v.Checks) != 0 {
		t.Fatal(v, e)
	}
	r := Request{Enabled: true, Names: []string{"worker.exe"}, Source: in.Complete}
	if s.Configure(in, r, at) == nil {
		t.Fatal("implicit consent")
	}
	r.Consent = true
	if e = s.Configure(in, r, at); e != nil {
		t.Fatal(e)
	}
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(append(raw, ' ')); e == nil {
		t.Fatal("noncanonical state accepted")
	}
	if s.Configure(in, r, at) == nil {
		t.Fatal("stale revision accepted")
	}
	r.ExpectedRevision = 1
	r.Names = []string{"Worker.exe"}
	if s.Configure(in, r, at) == nil {
		t.Fatal("guessed case accepted")
	}
	r.Names = []string{"worker.exe"}
	r.Source = &windowsfullprocesses.Complete{}
	if s.Configure(in, r, at) == nil {
		t.Fatal("changed review accepted")
	}
}
func TestWindowsProcessWatchPresenceIsNotRunningOrHealth(t *testing.T) {
	in, at := fixture(t)
	s := New()
	if e := s.Configure(in, Request{Enabled: true, Names: []string{"worker.exe"}, Consent: true, Source: in.Complete}, at); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name               string
		count, unavailable int
		status             string
		hide               bool
	}{{"present", 1, 0, "present", false}, {"absent", 0, 0, "not_observed", false}, {"unidentified", 0, 1, "unknown", true}, {"positive despite unidentified", 1, 1, "present", false}} {
		t.Run(tc.name, func(t *testing.T) {
			copy := in
			sample := *in.Complete
			copy.Complete = &sample
			copy.Counts = map[string]int{"worker.exe": tc.count}
			copy.UnavailableNames = tc.unavailable
			if tc.count+tc.unavailable > sample.Manifest.RowCount {
				sample.Manifest.RowCount = 2
				sample.Manifest.RowsBytes = 200
				sample.Manifest.RowsSHA256 = strings.Repeat("6", 64)
				sample.ManifestSHA256, _ = windowsfullprocesses.ManifestDigest(sample.Manifest)
			}
			v, e := s.View(copy, at)
			if e != nil || v.Checks[0].Status != tc.status || (v.Checks[0].Matches == nil) != tc.hide {
				t.Fatal(v, e)
			}
			raw, _ := json.Marshal(v)
			if strings.Contains(string(raw), "running") || strings.Contains(string(raw), "healthy") || strings.Contains(string(raw), "pid") {
				t.Fatal("extra authority or PID join")
			}
		})
	}
	for _, kind := range []string{"stale", "future", "grant", "missing", "identity", "expired"} {
		t.Run(kind, func(t *testing.T) {
			copy := in
			sample := *in.Complete
			copy.Complete = &sample
			now := at
			switch kind {
			case "stale":
				now = at.Add(MaxAge)
			case "future":
				sample.ReceivedAt = at.Add(time.Second)
			case "grant":
				sample.Manifest.GrantID = strings.Repeat("7", 32)
				sample.Manifest.GenerationID, _ = windowsfullprocesses.GenerationID(in.DeviceID, sample.Manifest.GrantID, 1)
				sample.ManifestSHA256, _ = windowsfullprocesses.ManifestDigest(sample.Manifest)
			case "missing":
				copy.Complete = nil
			case "identity":
				copy.CertificateHash = strings.Repeat("8", 64)
			case "expired":
				copy.AuthorityUntil = at
			}
			v, e := s.View(copy, now)
			if e == nil && (v.Status != "unknown" || v.Checks[0].Matches != nil || v.Source != nil) {
				t.Fatal("untrusted counts visible", v)
			}
		})
	}
	in.Complete = nil
	if e := s.Configure(in, Request{Names: []string{}, ExpectedRevision: 1}, at.Add(time.Second)); e != nil {
		t.Fatal("cannot disable without source", e)
	}
}

func TestWindowsProcessWatchNameBoundsAndPolicyClockFloor(t *testing.T) {
	for _, names := range [][]string{nil, {"same.exe", "same.exe"}, {"C:\\private.exe"}, {"path/name.exe"}, {strings.Repeat("x", 260)}, {"1", "2", "3", "4", "5", "6", "7", "8", "9"}} {
		if _, e := Names(names); e == nil {
			t.Fatal("invalid selection", names)
		}
	}
	names, e := Names([]string{" worker.exe ", "Worker.exe", "worker.exe", "α.exe"})
	if e != nil || len(names) != 4 {
		t.Fatal("spelling normalized", e)
	}
	in, at := fixture(t)
	s := New()
	if e := s.Configure(in, Request{Enabled: true, Names: []string{"worker.exe"}, Consent: true, Source: in.Complete}, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.View(in, at); e == nil {
		t.Fatal("policy from the future")
	}
}
