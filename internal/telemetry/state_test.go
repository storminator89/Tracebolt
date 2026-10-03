package telemetry

import (
	"encoding/json"
	"errors"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"strings"
	"sync"
	"testing"
	"time"
)

func sample(t *testing.T, at time.Time) []byte {
	t.Helper()
	d := collector.Snapshot()
	d.LastSeen = at
	d.CPU.CollectedAt = at
	d.Memory.CollectedAt = at
	d.Disk.CollectedAt = at
	for i := range d.Evidence {
		d.Evidence[i].CollectedAt = at
	}
	raw, err := EncodeForTransport(d)
	if err != nil {
		t.Fatal(err)
	}
	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.GeneratedAt = at
	raw, err = json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func edit(t *testing.T, raw []byte, fn func(map[string]any)) []byte {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	fn(obj)
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func obs(m map[string]any) map[string]any { return m["observation"].(map[string]any) }
func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestStateAwaitingAcceptedStaleAndNoFallback(t *testing.T) {
	now := time.Now().UTC()
	s := NewState()
	if st := s.Status(now); st.State != "awaiting" || st.CollectedAt != nil || st.ReceivedAt != nil || st.AcceptedSamples != 0 || st.ManagerStartedAt.IsZero() {
		t.Fatalf("bad initial status: %+v", st)
	}
	d := s.Device(now)
	if d.CPU.Value != nil || d.Status != "unknown" || !d.LastSeen.IsZero() || len(d.Evidence) != 0 {
		t.Fatalf("initial device fabricated a sample: %+v", d)
	}
	raw := sample(t, now)
	receipt, err := s.Accept(raw, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Sequence != 1 || receipt.DeviceID != DeviceID || !receipt.CollectedAt.Equal(now) {
		t.Fatal(receipt)
	}
	fresh := s.Device(now.Add(time.Second))
	if fresh.Status != "unknown" || fresh.Synthetic || fresh.Source != "sandbox" || len(fresh.Evidence) != 7 {
		t.Fatalf("bad accepted sample: %+v", fresh)
	}
	if fresh.Evidence[6].ID != "local-agent-transport" || !strings.Contains(fresh.Evidence[6].Detail, "loopback development transport") {
		t.Fatal("missing transport provenance")
	}
	st := s.Status(now.Add(MaxSampleAge + time.Second))
	if st.State != "stale" || st.AcceptedSamples != 1 {
		t.Fatal(st)
	}
	stale := s.Device(now.Add(MaxSampleAge + time.Second))
	if stale.CPU.Value != nil && stale.CPU.Quality != "stale" {
		t.Fatal("stale metric presented as fresh")
	}
	if !stale.LastSeen.Equal(now) {
		t.Fatal("stale sample was silently recollected")
	}
	if stale.Evidence[6].Quality != "stale" {
		t.Fatal("transport evidence did not age")
	}
}
func TestRejectMalformedAndUnsafeBundles(t *testing.T) {
	now := time.Now().UTC()
	raw := sample(t, now)
	cases := map[string]func(map[string]any){
		"missing required":           func(m map[string]any) { delete(obs(m), "synthetic") },
		"unknown field":              func(m map[string]any) { obs(m)["hostname"] = "private-host" },
		"case insensitive key":       func(m map[string]any) { obs(m)["Synthetic"] = obs(m)["synthetic"]; delete(obs(m), "synthetic") },
		"null array":                 func(m map[string]any) { obs(m)["tags"] = nil },
		"null bool":                  func(m map[string]any) { obs(m)["synthetic"] = nil },
		"ip":                         func(m map[string]any) { obs(m)["ip"] = "192.0.2.3" },
		"foreign identity":           func(m map[string]any) { obs(m)["id"] = "customer-123" },
		"host label":                 func(m map[string]any) { obs(m)["name"] = "my-hostname" },
		"wrong platform":             func(m map[string]any) { m["platform"] = "windows" },
		"wrong observation platform": func(m map[string]any) { obs(m)["platform"] = "windows" },
		"unknown schema":             func(m map[string]any) { m["schemaVersion"] = "tracebolt.support.v2" },
		"unknown version":            func(m map[string]any) { m["version"] = "999" },
		"unknown architecture":       func(m map[string]any) { m["architecture"] = "host-user-id" },
		"cpu outside range":          func(m map[string]any) { obs(m)["cpu"].(map[string]any)["value"] = 101 },
		"unknown with value":         func(m map[string]any) { v := obs(m)["cpu"].(map[string]any); v["value"] = 12; v["quality"] = "unknown" },
		"healthy with null": func(m map[string]any) {
			v := obs(m)["cpu"].(map[string]any)
			v["value"] = nil
			v["quality"] = "healthy"
		},
		"fake overall health":  func(m map[string]any) { obs(m)["status"] = "healthy" },
		"synthetic":            func(m map[string]any) { obs(m)["synthetic"] = true },
		"private tag":          func(m map[string]any) { obs(m)["tags"] = []any{"account"} },
		"case history":         func(m map[string]any) { obs(m)["caseIds"] = []any{"customer-case"} },
		"fake trend":           func(m map[string]any) { obs(m)["trend"] = []any{20} },
		"missing evidence":     func(m map[string]any) { obs(m)["evidence"] = []any{} },
		"missing capabilities": func(m map[string]any) { obs(m)["capabilities"] = []any{} },
		"fake capability": func(m map[string]any) {
			for _, v := range obs(m)["capabilities"].([]any) {
				c := v.(map[string]any)
				if c["id"] == "systemd" {
					c["status"] = "supported"
				}
			}
		},
		"duplicate capability": func(m map[string]any) { v := obs(m)["capabilities"].([]any); v[1] = v[0] },
		"duplicate evidence":   func(m map[string]any) { v := obs(m)["evidence"].([]any); v[1] = v[0] },
		"zero timestamp":       func(m map[string]any) { obs(m)["lastSeen"] = "0001-01-01T00:00:00Z" },
		"late field": func(m map[string]any) {
			m["generatedAt"] = now.Add(2 * time.Second).Format(time.RFC3339Nano)
			obs(m)["cpu"].(map[string]any)["collectedAt"] = now.Add(time.Second).Format(time.RFC3339Nano)
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewState().Accept(edit(t, raw, fn), now); code(err) != "invalid_bundle" {
				t.Fatalf("expected invalid_bundle, got %v (%s)", err, code(err))
			}
		})
	}
	malformed := map[string][]byte{"empty": {}, "malformed": []byte("{"), "trailing": append(append([]byte{}, raw...), []byte("{}")...), "duplicate top": []byte(strings.Replace(string(raw), `"product":"Tracebolt"`, `"product":"Tracebolt","product":"Tracebolt"`, 1)), "duplicate nested": []byte(strings.Replace(string(raw), `"synthetic":false`, `"synthetic":false,"synthetic":false`, 1)), "invalid utf8": append([]byte{'"', 0xff}, '"')}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := NewState().Accept(input, now); code(err) != "invalid_bundle" {
				t.Fatalf("accepted malformed bundle: %v", err)
			}
		})
	}
	if _, err := NewState().Accept([]byte(strings.Repeat(" ", MaxBodyBytes+1)), now); code(err) != "payload_too_large" {
		t.Fatal(err)
	}
}
func TestTimeReplayAndRestartBoundary(t *testing.T) {
	now := time.Now().UTC()
	raw := sample(t, now)
	s := NewState()
	for _, tc := range []struct {
		name, field, want string
		at                time.Time
	}{{"old generated", "generatedAt", "stale_sample", now.Add(-MaxSampleAge - time.Second)}, {"future generated", "generatedAt", "future_sample", now.Add(FutureSkew + time.Second)}, {"old field", "cpu", "stale_sample", now.Add(-MaxSampleAge - time.Second)}, {"future field", "cpu", "future_sample", now.Add(FutureSkew + time.Second)}} {
		t.Run(tc.name, func(t *testing.T) {
			input := edit(t, raw, func(m map[string]any) {
				if tc.field == "generatedAt" {
					m[tc.field] = tc.at.Format(time.RFC3339Nano)
				} else {
					obs(m)[tc.field].(map[string]any)["collectedAt"] = tc.at.Format(time.RFC3339Nano)
				}
			})
			if _, err := s.Accept(input, now); code(err) != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
	if _, err := s.Accept(raw, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(raw, now.Add(time.Second)); code(err) != "replayed_sample" {
		t.Fatal(err)
	}
	if !s.Status(now).ReceivedAt.Equal(now) {
		t.Fatal("replay refreshed receipt")
	}
	if _, err := s.Accept(sample(t, now.Add(-time.Second)), now); code(err) != "replayed_sample" {
		t.Fatal(err)
	}
	if receipt, err := s.Accept(sample(t, now.Add(time.Second)), now.Add(time.Second)); err != nil || receipt.Sequence != 2 {
		t.Fatalf("new sample: %+v %v", receipt, err)
	}
	// Replay protection intentionally resets with the explicit in-memory manager
	// epoch; fresh prior-process samples are not authenticated device identity.
	restarted := NewState()
	if receipt, err := restarted.Accept(raw, now); err != nil || receipt.Sequence != 1 || receipt.ManagerStartedAt.Equal(s.Status(now).ManagerStartedAt) {
		t.Fatalf("bad restart scope: %v", err)
	}
}
func TestStateCopiesAndConcurrency(t *testing.T) {
	now := time.Now().UTC()
	s := NewState()
	if _, err := s.Accept(sample(t, now), now); err != nil {
		t.Fatal(err)
	}
	original := s.Device(now)
	d := s.Device(now)
	d.Evidence[0].Value = "changed"
	d.Tags[0] = "changed"
	d.Capabilities[0].Detail = "changed"
	if d.CPU.Value != nil {
		*d.CPU.Value = 99
	}
	again := s.Device(now)
	if again.Evidence[0].Value != original.Evidence[0].Value || again.Tags[0] != original.Tags[0] || again.Capabilities[0].Detail != original.Capabilities[0].Detail {
		t.Fatal("mutable state escaped")
	}
	if again.CPU.Value != nil && *again.CPU.Value != *original.CPU.Value {
		t.Fatal("metric pointer escaped")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.Device(now)
				s.Status(now)
			}
		}()
	}
	wg.Wait()
}

func TestMixedAgeObservationExpiresWithoutNewPost(t *testing.T) {
	now := time.Now().UTC()
	raw := sample(t, now)
	raw = edit(t, raw, func(m map[string]any) {
		obs(m)["cpu"].(map[string]any)["collectedAt"] = now.Add(-MaxSampleAge + time.Second).Format(time.RFC3339Nano)
	})
	s := NewState()
	if _, err := s.Accept(raw, now); err != nil {
		t.Fatal(err)
	}
	if s.Status(now).State != "fresh" {
		t.Fatal("initial valid sample was stale")
	}
	later := now.Add(2 * time.Second)
	if s.Status(later).State != "stale" {
		t.Fatal("old field failed to expire")
	}
	d := s.Device(later)
	if d.CPU.Value != nil && d.CPU.Quality != "stale" {
		t.Fatal("old field remains healthy")
	}
	if !d.LastSeen.Equal(now) || s.Status(later).AcceptedSamples != 1 {
		t.Fatal("aging resampled data")
	}
}

func TestPreviewValidatesActualBundleAtExactBodyBoundary(t *testing.T) {
	at := time.Unix(1800000000, 123456789).UTC()
	var b bundle.Bundle
	if err := json.Unmarshal(sample(t, at), &b); err != nil {
		t.Fatal(err)
	}
	for n := range b.Observation.Evidence {
		b.Observation.Evidence[n].Detail = ""
		b.Observation.Evidence[n].Value = ""
		b.Observation.Evidence[n].Source = ""
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	remaining := MaxBodyBytes - len(raw)
	for n := range b.Observation.Evidence {
		for _, field := range []*string{&b.Observation.Evidence[n].Detail, &b.Observation.Evidence[n].Value, &b.Observation.Evidence[n].Source} {
			count := remaining
			if count > 4096 {
				count = 4096
			}
			*field = strings.Repeat("x", count)
			remaining -= count
		}
	}
	if remaining != 0 {
		t.Fatal("fixture did not fill accepted envelope")
	}
	raw, err = json.Marshal(b)
	if err != nil || len(raw) != MaxBodyBytes {
		t.Fatal("fixture boundary mismatch")
	}
	if _, err = bundle.Encode(b.Observation); err == nil {
		t.Fatal("fixture must distinguish fresh generated envelope from received envelope")
	}
	for range 30 {
		if _, err = decodeBundle(raw, at); err != nil {
			t.Fatal("exact original-envelope boundary rejected:", err)
		}
	}
	if _, err = decodeBundle(append(raw, ' '), at); code(err) != "payload_too_large" {
		t.Fatal("over-bound original envelope accepted")
	}
}
