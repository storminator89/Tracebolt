package lanstore

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/lantrust"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureAgent() lantrust.Agent {
	now := time.Now().UTC()
	return lantrust.Agent{ID: "agent_" + strings.Repeat("1", 32), Label: "Fixture agent", FingerprintSHA256: strings.Repeat("a", 64), ApprovedAt: now, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
}
func sampleFrame(t *testing.T) Frame {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux fixture collector")
	}
	raw, err := bundle.Encode(collector.Snapshot())
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	var observation bundle.Bundle
	if json.Unmarshal(raw, &observation) != nil {
		t.Fatal("fixture JSON failed")
	}
	return Frame{SchemaVersion: FrameVersion, Sequence: 1, Observation: observation}
}
func TestFrameStrictnessAndVersionCompatibility(t *testing.T) {
	frame := sampleFrame(t)
	frame.Observation.Version = "future-compatible-agent-build"
	raw, _ := json.Marshal(frame)
	if _, err := ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal("application version was improperly coupled to wire version")
	}
	bad := []string{strings.Replace(string(raw), `"sequence":1`, `"sequence":1,"sequence":2`, 1), strings.Replace(string(raw), `"schemaVersion":`, `"SchemaVersion":`, 1), strings.Replace(string(raw), `"sequence":1`, `"sequence":0`, 1), strings.Replace(string(raw), FrameVersion, "unknown.protocol", 1), strings.TrimSuffix(string(raw), "}") + `,"agentId":"forged"}`, strings.Repeat(" ", MaxFrameBytes+1)}
	for _, input := range bad {
		if _, err := ValidateFrame([]byte(input), time.Now()); err == nil {
			t.Fatal("invalid or identity-overriding frame accepted")
		}
	}
	frame.Observation.Observation.LastSeen = time.Now().Add(time.Hour)
	raw, _ = json.Marshal(frame)
	if _, err := ValidateFrame(raw, time.Now()); err == nil {
		t.Fatal("future frame accepted")
	}
}
func TestDurableApprovalReplayAndRevocation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux manager storage")
	}
	path := filepath.Join(t.TempDir(), "private", "agents.db")
	state, err := Open(path)
	if err != nil {
		t.Fatal("state open failed")
	}
	agent := fixtureAgent()
	if err = state.Save(context.Background(), agent); err != nil {
		t.Fatal("fixture public approval save failed")
	}
	frame := sampleFrame(t)
	raw, _ := json.Marshal(frame)
	first, err := state.SaveObservation(context.Background(), agent, frame.Sequence, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, time.Now().UTC())
	if err != nil {
		t.Fatal("observation save failed")
	}
	if err = state.Close(); err != nil {
		t.Fatal("close failed")
	}
	state, err = Open(path)
	if err != nil {
		t.Fatal("durable reopen failed")
	}
	defer state.Close()
	agents, err := state.Load(context.Background())
	if err != nil || len(agents) != 1 {
		t.Fatal("approval did not persist")
	}
	duplicate, err := state.SaveObservation(context.Background(), agent, frame.Sequence, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, time.Now().UTC())
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("duplicate refreshed freshness across restart")
	}
	if _, err = state.SaveObservation(context.Background(), agent, frame.Sequence, frame.Observation.GeneratedAt, frame.Observation.Observation, append(raw, ' '), time.Now().UTC()); !errors.Is(err, ErrReplay) {
		t.Fatal("conflicting replay accepted")
	}
	devices, err := state.Devices(context.Background(), agents, time.Now().Add(3*time.Minute))
	if err != nil || len(devices) != 1 || devices[0].ID != agent.ID || devices[0].Source != "lan" || devices[0].CPU.Quality == "healthy" {
		t.Fatal("identity mapping or stale quality failed")
	}
	agent.RevokedAt = time.Now().UTC()
	if err = state.Save(context.Background(), agent); err != nil {
		t.Fatal("revocation persist failed")
	}
	if _, err = state.SaveObservation(context.Background(), agent, 2, time.Now(), frame.Observation.Observation, raw, time.Now()); !errors.Is(err, ErrBinding) {
		t.Fatal("revoked agent can store telemetry")
	}
	agent.RevokedAt = time.Time{}
	if err = state.Save(context.Background(), agent); !errors.Is(err, ErrBinding) {
		t.Fatal("revocation tombstone removed")
	}
}
func TestStorageRejectsSymlinksAndInsecureExistingFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux permissions")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if os.WriteFile(target, []byte("fixture"), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(target, link) != nil {
		t.Fatal("fixture symlink failed")
	}
	if s, err := Open(link); err == nil {
		s.Close()
		t.Fatal("symlink database accepted")
	}
	insecure := filepath.Join(dir, "insecure")
	if os.WriteFile(insecure, []byte{}, 0644) != nil {
		t.Fatal("fixture write failed")
	}
	if s, err := Open(insecure); err == nil {
		s.Close()
		t.Fatal("insecure existing database accepted")
	}
	parentLink := filepath.Join(dir, "parent-link")
	if os.Symlink(dir, parentLink) != nil {
		t.Fatal("fixture symlink failed")
	}
	if s, err := Open(filepath.Join(parentLink, "new.db")); err == nil {
		s.Close()
		t.Fatal("symlink parent accepted")
	}
}

func TestPrivateDirectorySidecarsAndColumnBinding(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux permissions")
	}
	parent := t.TempDir()
	public := filepath.Join(parent, "public")
	if os.Mkdir(public, 0755) != nil {
		t.Fatal("fixture directory failed")
	}
	if state, err := Open(filepath.Join(public, "state.db")); err == nil {
		state.Close()
		t.Fatal("nonprivate state directory accepted")
	}
	private := filepath.Join(parent, "private")
	if os.Mkdir(private, 0700) != nil {
		t.Fatal("fixture directory failed")
	}
	path := filepath.Join(private, "state.db")
	if os.WriteFile(path+"-wal", []byte{}, 0644) != nil {
		t.Fatal("fixture sidecar failed")
	}
	if state, err := Open(path); err == nil {
		state.Close()
		t.Fatal("insecure sidecar accepted")
	}
	if os.Remove(path+"-wal") != nil {
		t.Fatal("fixture cleanup failed")
	}
	state, err := Open(path)
	if err != nil {
		t.Fatal("private state failed")
	}
	defer state.Close()
	agent := fixtureAgent()
	if state.Save(context.Background(), agent) != nil {
		t.Fatal("save failed")
	}
	if _, err := state.db.Exec("UPDATE lan_agents SET fingerprint=? WHERE id=?", strings.Repeat("b", 64), agent.ID); err != nil {
		t.Fatal("fixture corruption failed")
	}
	if _, err := state.Load(context.Background()); err == nil {
		t.Fatal("column/body identity mismatch accepted")
	}
}
