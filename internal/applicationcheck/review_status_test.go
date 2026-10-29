package applicationcheck

import (
	"testing"
	"time"
)

func TestReviewStatusBindsGenerationAndFreshSnapshot(t *testing.T) {
	now := time.Now().UTC()
	c := Config{schema: ConfigSchemaVersionV2, enabled: true, interval: time.Minute, targets: []target{{Kind: kindDNS, ID: "fixture"}}}
	m := New(c)
	m.now = func() time.Time { return now }
	m.items[0] = Result{Kind: kindDNS, ID: "fixture", State: "ok", Reason: "dns_resolved", ObservedAt: &now}
	s := &Settings{mode: "managed", config: c, saved: savedSettings{Generation: "first"}, monitor: m}
	v, g, ok := s.ReviewStatus()
	if !ok || g != "first" || !v.Enabled || len(v.Items) != 1 || v.Items[0].Reason != "dns_resolved" {
		t.Fatal("wrong snapshot")
	}
	s.operation.Lock()
	s.mu.Lock()
	s.saved.Generation = "second"
	s.monitor = New(c)
	s.mu.Unlock()
	s.operation.Unlock()
	v, g, ok = s.ReviewStatus()
	if !ok || g != "second" || v.Items[0].Reason != "not_checked" {
		t.Fatal("old observation survived generation change")
	}
	s.mu.Lock()
	s.blocked = true
	s.mu.Unlock()
	if _, _, ok = s.ReviewStatus(); ok {
		t.Fatal("blocked generation accepted")
	}
}
