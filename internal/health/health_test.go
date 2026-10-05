package health

import (
	"bytes"
	"encoding/json"
	"fmt"
	"localrmm/internal/model"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var epoch = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func sample(at time.Time, disk float64) Input {
	return Input{DeviceID: "agent_test", Authorized: true, ReceivedAt: at, Disk: model.Metric{Value: &disk, Unit: "%", Quality: "healthy", CollectedAt: at}, Services: map[string]ServiceSample{"sshd.service": {State: "active", ObservedAt: at}}}
}
func tick(s *State, seconds int, disk float64) {
	at := epoch.Add(time.Duration(seconds) * time.Second)
	s.Evaluate(sample(at, disk), at)
}
func TestFilesystemMinimumDurationHysteresisAndOneIncident(t *testing.T) {
	s := New()
	for sec := 0; sec < 120; sec += 30 {
		tick(&s, sec, 94)
		if len(s.Incidents) != 0 {
			t.Fatal("opened early")
		}
	}
	tick(&s, 120, 94)
	if len(s.Incidents) != 1 || s.Checks[1].State != "open" {
		t.Fatalf("not opened: %+v", s)
	}
	id := s.Incidents[0].ID
	for sec := 150; sec <= 240; sec += 30 {
		tick(&s, sec, 96)
	}
	if len(s.Incidents) != 1 || s.Incidents[0].ID != id {
		t.Fatal("duplicate incident")
	}
	for sec := 270; sec <= 360; sec += 30 {
		tick(&s, sec, 87)
	}
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("hysteresis lost")
	}
	tick(&s, 390, 84)
	tick(&s, 420, 84)
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("recovered early")
	}
	tick(&s, 450, 84)
	if s.Incidents[0].ResolvedAt == nil || s.Incidents[0].ClosedReason != "recovered" {
		t.Fatal("not recovered")
	}
	for sec := 480; sec <= 600; sec += 30 {
		tick(&s, sec, 91)
	}
	if len(s.Incidents) != 2 || s.Incidents[0].ID == id {
		t.Fatal("new outage needs distinct incident")
	}
}
func TestRepeatedStaleMissingAndInvalidSamplesNeverEarnDuration(t *testing.T) {
	s := New()
	same := sample(epoch, 99)
	for sec := 0; sec <= 300; sec += 30 {
		s.Evaluate(same, epoch.Add(time.Duration(sec)*time.Second))
	}
	if s.open("filesystem:root") != nil || s.Checks[1].State != "unknown" {
		t.Fatalf("repeated sample opened metric: %+v", s)
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), -1, 101} {
		s = New()
		in := sample(epoch, v)
		s.Evaluate(in, epoch)
		if s.Checks[1].State != "unknown" {
			t.Fatal("invalid percentage accepted")
		}
	}
	for _, quality := range []string{"unknown", "denied", "stale"} {
		s = New()
		in := sample(epoch, 99)
		in.Disk.Quality = quality
		s.Evaluate(in, epoch)
		if s.Checks[1].State != "unknown" {
			t.Fatal("invalid quality accepted")
		}
	}
	s = New()
	tick(&s, 0, 99)
	tick(&s, 30, 99)
	bad := sample(epoch.Add(60*time.Second), 99)
	bad.Disk.Value = nil
	s.Evaluate(bad, epoch.Add(60*time.Second))
	tick(&s, 90, 99)
	tick(&s, 120, 99)
	if len(s.Incidents) != 0 {
		t.Fatal("unknown did not reset pending")
	}
}
func TestOfflineUsesAcceptedReceiptNotOldCaptureOrPageReads(t *testing.T) {
	s := New()
	in := sample(epoch, 10)
	for sec := 0; sec <= 180; sec += 30 {
		s.Evaluate(in, epoch.Add(time.Duration(sec)*time.Second))
		if len(s.Incidents) != 0 {
			t.Fatal("offline opened before grace")
		}
	}
	s.Evaluate(in, epoch.Add(210*time.Second))
	if len(s.Incidents) != 1 || s.Incidents[0].Kind != "offline" {
		t.Fatal("missing contact not detected")
	}
	// Fresh contact is not immediate recovery: require a continuous one-minute window.
	tick(&s, 240, 10)
	tick(&s, 270, 10)
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("recovered too early")
	}
	tick(&s, 300, 10)
	if s.Incidents[0].ResolvedAt == nil {
		t.Fatal("contact did not recover")
	}
	s = New()
	s.Evaluate(Input{Authorized: true}, epoch)
	if s.Checks[0].State != "unknown" {
		t.Fatal("never observed device declared offline")
	}
}
func TestExplicitServiceUnknownAndRemoval(t *testing.T) {
	s := New()
	if e := s.SetServices([]string{"sshd.service"}, epoch); e != nil {
		t.Fatal(e)
	}
	for sec := 0; sec <= 120; sec += 30 {
		at := epoch.Add(time.Duration(sec) * time.Second)
		in := sample(at, 20)
		in.Services["sshd.service"] = ServiceSample{"inactive", at}
		s.Evaluate(in, at)
	}
	if len(s.Incidents) != 1 || s.Incidents[0].Kind != "service" {
		t.Fatal("service not opened")
	}
	id := s.Incidents[0].ID
	if e := s.Acknowledge(id, epoch.Add(130*time.Second)); e != nil {
		t.Fatal(e)
	}
	ack := *s.Incidents[0].AcknowledgedAt
	if e := s.Acknowledge(id, epoch.Add(140*time.Second)); e != nil || !s.Incidents[0].AcknowledgedAt.Equal(ack) {
		t.Fatal("ack is not idempotent")
	}
	in := sample(epoch.Add(150*time.Second), 20)
	in.Services = map[string]ServiceSample{}
	s.Evaluate(in, epoch.Add(150*time.Second))
	if s.Checks[2].State != "unknown" || s.Incidents[0].ResolvedAt != nil {
		t.Fatal("missing service fabricated recovery")
	}
	if e := s.SetServices([]string{}, epoch.Add(160*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Incidents[0].ClosedReason != "monitoring_stopped" {
		t.Fatal("removal claimed recovery")
	}
}
func TestMaintenanceIsBoundedSuppressesOnlyNewIncidents(t *testing.T) {
	s := New()
	if s.Maintain(241, epoch) == nil {
		t.Fatal("unbounded maintenance")
	}
	s.Maintain(15, epoch)
	for sec := 0; sec <= 900; sec += 30 {
		tick(&s, sec, 99)
	}
	if len(s.Incidents) != 0 {
		t.Fatal("maintenance credited suppressed time")
	}
	for sec := 930; sec <= 1020; sec += 30 {
		tick(&s, sec, 99)
	}
	if len(s.Incidents) != 1 {
		t.Fatal("maintenance did not expire")
	}
	s.Maintain(60, epoch.Add(1030*time.Second))
	for sec := 1050; sec <= 1110; sec += 30 {
		tick(&s, sec, 50)
	}
	if s.Incidents[0].ResolvedAt == nil {
		t.Fatal("maintenance blocked genuine recovery")
	}
}
func TestManagerGapClockRollbackAndAuthorityLoss(t *testing.T) {
	s := New()
	tick(&s, 0, 99)
	tick(&s, 30, 99)
	tick(&s, 600, 99)
	if len(s.Incidents) != 0 {
		t.Fatal("manager gap credited")
	}
	s.Evaluate(sample(epoch.Add(610*time.Second), 99), epoch.Add(590*time.Second))
	if s.Checks[1].State != "unknown" {
		t.Fatal("clock rollback accepted")
	}
	for sec := 630; sec <= 750; sec += 30 {
		tick(&s, sec, 99)
	}
	if len(s.Incidents) != 1 {
		t.Fatal("expected incident")
	}
	s.Evaluate(Input{Authorized: false}, epoch.Add(780*time.Second))
	if s.Checks[1].State != "unknown" || s.Incidents[0].ResolvedAt != nil {
		t.Fatal("revocation fabricated recovery")
	}
	v := s.View("a", epoch.Add(time.Hour))
	if v.Status != "unknown" {
		t.Fatal("stopped monitor looked current")
	}
}
func TestSettingsValidationAndHistoryBound(t *testing.T) {
	for _, names := range [][]string{nil, {"a.service", "a.service"}, {"../../a.service"}, {"a.service;reboot"}, {"foo"}, {"a\n.service"}} {
		if _, e := Services(names); e == nil {
			t.Fatalf("accepted %q", names)
		}
	}
	s := New()
	for i := 0; i < 140; i++ {
		at := epoch.Add(time.Duration(i) * time.Minute)
		s.Incidents = append(s.Incidents, Incident{ID: fmt.Sprint(i), Key: "filesystem:root", Kind: "filesystem", Target: "/", OpenedAt: at, LastObservedAt: at, ResolvedAt: stamp(at), ClosedReason: "recovered"})
	}
	s.prune(epoch.Add(3 * time.Hour))
	if len(s.Incidents) != 100 {
		t.Fatal("history not bounded")
	}
	s.prune(epoch.Add(Retention + 24*time.Hour))
	if len(s.Incidents) != 0 {
		t.Fatal("old history retained")
	}
}

func TestViewOriginalAgeOutlivesEvaluationFreshness(t *testing.T) {
	s := New()
	in := sample(epoch, 40)
	now := epoch.Add(110 * time.Second)
	s.Evaluate(in, now)
	view := s.View("agent", now.Add(20*time.Second))
	if view.Status != "unknown" || view.Checks[1].State != "unknown" || view.Checks[1].Value != nil {
		t.Fatal("fresh evaluation relabeled old measurement")
	}
	s.Maintain(15, epoch)
	view = s.View("agent", epoch.Add(16*time.Minute))
	if view.MaintenanceUntil != nil || view.Status == "maintenance" {
		t.Fatal("expired maintenance remains active")
	}
}

func TestHealthDelayedSamplesDoNotCreditMaintenanceOrDisabledTime(t *testing.T) {
	s := New()
	s.Maintain(15, epoch)
	// First observation after expiry was captured during maintenance.
	now := epoch.Add(901 * time.Second)
	in := sample(now.Add(-100*time.Second), 95)
	in.ReceivedAt = now
	s.Evaluate(in, now)
	for _, seconds := range []int{931, 961, 991, 1021} {
		at := epoch.Add(time.Duration(seconds) * time.Second)
		in = sample(at.Add(-10*time.Second), 95)
		in.ReceivedAt = at
		s.Evaluate(in, at)
		if len(s.Incidents) != 0 {
			t.Fatal("credited pre-confirmation measurement time")
		}
	}
	now = epoch.Add(1051 * time.Second)
	in = sample(now.Add(-10*time.Second), 95)
	in.ReceivedAt = now
	s.Evaluate(in, now)
	if len(s.Incidents) != 1 {
		t.Fatal("new confirmation window did not open")
	}
}

// This is synthetic public contract data, never a copied endpoint observation.
func TestHealthViewGoFixture(t *testing.T) {
	s := New()
	if e := s.SetServices([]string{"sshd.service"}, epoch); e != nil {
		t.Fatal(e)
	}
	now := epoch
	for seconds := 0; seconds <= 150; seconds += 30 {
		now = epoch.Add(time.Duration(seconds) * time.Second)
		in := sample(now.Add(-10*time.Second), 95)
		in.ReceivedAt = now
		s.Evaluate(in, now)
	}
	view := s.View("agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now)
	if len(view.Incidents) != 1 || !view.Incidents[0].LastObservedAt.Before(view.Incidents[0].OpenedAt) {
		t.Fatal("fixture must preserve delayed source time")
	}
	raw, e := json.MarshalIndent(view, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "web", "src", "health-go-fixture.json")
	if os.Getenv("TRACEBOLT_UPDATE_HEALTH_FIXTURE") == "1" {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	existing, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(existing, raw) {
		t.Fatal("health Go/UI fixture differs; regenerate with TRACEBOLT_UPDATE_HEALTH_FIXTURE=1", e)
	}
}
