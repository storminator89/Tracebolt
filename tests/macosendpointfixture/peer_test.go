package main

// These tests are deliberately inert: no keys, certificates, listeners, PTYs,
// child processes, native collectors or real private enrollment state.
import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
)

func TestBlockedEntryContract(t *testing.T) {
	var v struct {
		SchemaVersion string `json:"schemaVersion"`
		Status        string `json:"status"`
		Reason        string `json:"reason"`
		Simulated     bool   `json:"simulatedManager"`
		Started       bool   `json:"runtimeStarted"`
	}
	d := json.NewDecoder(strings.NewReader(blockedResult))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Status != "blocked" || v.Reason != "native_execution_gate_unavailable" || v.Started || !v.Simulated {
		t.Fatal("inert entry contract changed")
	}
}
func TestStrictBoundedControl(t *testing.T) {
	for _, v := range []string{`{"command":"start"}`, `{"command":"status"}`, `{"command":"arm_loss"}`, `{"command":"stop"}`, `{"command":"approve","fingerprint":"` + strings.Repeat("a", 64) + `","comparison":"` + strings.Repeat("b", 32) + `"}`} {
		if _, e := decodeCommand([]byte(v)); e != nil {
			t.Fatal("valid command rejected")
		}
	}
	for _, v := range []string{`{}`, `{"command":"execute"}`, `{"Command":"start"}`, `{"command":"start","command":"stop"}`, `{"command":"start","invitation":"secret"}`, `{"command":"start"} {}`, `{"command":"status","fingerprint":null}`, `{"command":"approve"}`, `{"command":"approve","fingerprint":"bad","comparison":"bad"}`, strings.Repeat("x", controlLimit+1)} {
		if _, e := decodeCommand([]byte(v)); e == nil {
			t.Fatal("invalid control accepted")
		}
	}
}

func sampleBasic(t *testing.T, at time.Time, seq uint64) (lanstore.Frame, []byte) {
	t.Helper()
	metric := func(source, quality string) model.Metric {
		return model.Metric{Unit: "%", Source: source, Quality: quality, CollectedAt: at}
	}
	cpu := "collector policy: CPU interval sampling not implemented"
	memory := "collector policy: VM utilization accounting not implemented; hw.memsize is capacity only"
	disk := "statfs(/); root filesystem f_blocks and f_bfree"
	d := model.Device{ID: "local-macos", Name: "Local macOS", Site: "Local machine", Group: "Local observations", Platform: "macos", OS: "macOS (version unavailable)", AgentVersion: "fixture", Source: "local", Status: "unknown", Uptime: "Unknown", LastSeen: at, CPU: metric(cpu, "unknown"), Memory: metric(memory, "unknown"), Disk: metric(disk, "denied")}
	for _, pair := range [][2]string{{"local-macos-os", "sysctl(kern.osproductversion)"}, {"local-macos-kernel", "sysctl(kern.osrelease)"}, {"local-macos-uptime", "sysctl(kern.boottime); elapsed wall-clock time since boot"}, {"local-macos-memory-capacity", "sysctl(hw.memsize); physical memory capacity in bytes"}, {"local-macos-cpu", cpu}, {"local-macos-memory", memory}, {"local-macos-disk", disk}, {"local-scope", "collector policy"}} {
		d.Evidence = append(d.Evidence, model.Evidence{ID: pair[0], Source: pair[1], Quality: "unknown", CollectedAt: at})
	}
	d.Evidence[6].Quality = "denied"
	b, e := bundle.Encode(d)
	if e != nil {
		t.Fatal("invalid synthetic test input")
	}
	var obs bundle.Bundle
	if json.Unmarshal(b, &obs) != nil {
		t.Fatal("invalid sample")
	}
	obs.GeneratedAt = at
	obs.Architecture = "arm64"
	f := lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: seq, Observation: obs}
	raw, e := json.Marshal(f)
	if e != nil {
		t.Fatal("invalid sample")
	}
	return f, raw
}
func TestBasicContractUnavailableTruthAndBoundedShape(t *testing.T) {
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	f, raw := sampleBasic(t, at, 1)
	if _, e := validateBasic(raw, at.Add(time.Second)); e != nil {
		t.Fatal("honest unavailable sample rejected")
	}
	if _, e := validateBasic(raw, at.Add(121*time.Second)); e == nil {
		t.Fatal("stale accepted")
	}
	for _, change := range []func(*lanstore.Frame){
		func(f *lanstore.Frame) {
			x := 0.0
			f.Observation.Observation.CPU.Value = &x
			f.Observation.Observation.CPU.Quality = "healthy"
		},
		func(f *lanstore.Frame) { f.Observation.Observation.Memory.Source = "host memory use" },
		func(f *lanstore.Frame) { f.Observation.Observation.Evidence[0].Source = "kern.version" },
		func(f *lanstore.Frame) { f.Observation.Observation.Evidence = f.Observation.Observation.Evidence[:7] },
		func(f *lanstore.Frame) { f.Observation.Platform = "darwin" },
		func(f *lanstore.Frame) { f.Observation.Architecture = "386" },
	} {
		g, _ := sampleBasic(t, at, 1)
		change(&g)
		b, _ := json.Marshal(g)
		if _, e := validateBasic(b, at); e == nil {
			t.Fatal("widened/false scope accepted")
		}
	}
	b, _ := json.Marshal(f)
	b = append(b[:len(b)-1], []byte(`,"inventory":{}}`)...)
	if _, e := validateBasic(b, at); e == nil {
		t.Fatal("expanded field accepted")
	}
	b = bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":2`), 1)
	if _, e := validateBasic(b, at); e == nil {
		t.Fatal("duplicate field accepted")
	}
	if _, e := validateBasic(make([]byte, lanstore.MaxFrameBytes+1), at); e == nil {
		t.Fatal("oversized frame accepted")
	}
}
func TestReceiptLossExactRetryAndUnchangedFirstReceiptTime(t *testing.T) {
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	m := receiptMemory{}
	f, b := sampleBasic(t, at, 1)
	first, dup, e := m.accept(b, f, fixtureID("agent", 1), at.Add(time.Second))
	if e != nil || dup {
		t.Fatal("first receipt failed")
	}
	again, dup, e := m.accept(bytes.Clone(b), f, fixtureID("agent", 1), at.Add(10*time.Second))
	if e != nil || !dup || !again.ReceivedAt.Equal(first.ReceivedAt) || !again.CollectedAt.Equal(first.CollectedAt) {
		t.Fatal("retry retimestamped")
	}
	altered := append(bytes.Clone(b), ' ')
	if _, _, e = m.accept(altered, f, fixtureID("agent", 1), at); e == nil {
		t.Fatal("semantic-only body accepted")
	}
	f2, b2 := sampleBasic(t, at.Add(11*time.Second), 2)
	r, dup, e := m.accept(b2, f2, fixtureID("agent", 1), at.Add(12*time.Second))
	if e != nil || dup || r.Sequence != 2 {
		t.Fatal("floor did not advance")
	}
	if _, _, e = m.accept(b, f, fixtureID("agent", 1), at.Add(13*time.Second)); e == nil {
		t.Fatal("old floor accepted")
	}
	f4, b4 := sampleBasic(t, at.Add(14*time.Second), 4)
	if _, _, e = m.accept(b4, f4, fixtureID("agent", 1), at.Add(15*time.Second)); e == nil {
		t.Fatal("skipped floor accepted")
	}
}
func TestPublicPeerStatusHasOnlyClosedBooleansAndCounts(t *testing.T) {
	raw, e := json.Marshal(peerStatus{})
	if e != nil {
		t.Fatal("status encoding failed")
	}
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil || len(v) != 12 {
		t.Fatal("status fields changed")
	}
	for _, x := range v {
		switch x.(type) {
		case bool, float64:
		default:
			t.Fatal("status leaked rich data")
		}
	}
	for _, forbidden := range []string{"invitation", "certificate", "body", "fingerprint", "collectedAt", "receivedAt", "path", "error"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("status exposed private material")
		}
	}
}
