package lanstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/lantrust"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDevicesCertificateExpiryUsesApprovalWithoutRenewing(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "private", "agents.db"))
	if err != nil {
		t.Fatal("fixture store failed")
	}
	defer state.Close()
	agent := fixtureAgent()
	for _, checked := range []time.Time{agent.ApprovedAt, agent.ExpiresAt, agent.ExpiresAt.Add(time.Hour)} {
		devices, err := state.Devices(context.Background(), []lantrust.Agent{agent}, checked)
		if err != nil || len(devices) != 1 {
			t.Fatal("operator expiry read failed")
		}
		d := devices[0]
		c := d.AgentCertificate
		if c == nil || c.Source != "manual-approval" || c.ExpiresAt == nil || !c.ExpiresAt.Equal(agent.ExpiresAt) || !c.CheckedAt.Equal(checked) {
			t.Fatal("operator read changed certificate expiry")
		}
		if d.Status != "unknown" || !d.LastSeen.IsZero() {
			t.Fatal("certificate expiry read established device connectivity")
		}
	}
	agent.RevokedAt = agent.ApprovedAt
	devices, err := state.Devices(context.Background(), []lantrust.Agent{agent}, agent.ApprovedAt)
	if err != nil || devices[0].Capabilities[0].Status != "denied" || !devices[0].AgentCertificate.ExpiresAt.Equal(agent.ExpiresAt) {
		t.Fatal("unexpired metadata hid revocation")
	}
	agent.ExpiresAt = time.Time{}
	devices, err = state.Devices(context.Background(), []lantrust.Agent{agent}, agent.ApprovedAt)
	if err != nil || devices[0].AgentCertificate.ExpiresAt != nil {
		t.Fatal("missing expiry was fabricated")
	}
}

func TestAgentTelemetryRejectsOperatorCertificateMetadata(t *testing.T) {
	frame := sampleFrame(t)
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	if strings.Contains(string(raw), "agentCertificate") {
		t.Fatal("existing endpoint wire shape changed")
	}
	if _, err = ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal("unchanged endpoint frame rejected")
	}
	for _, field := range []string{`null`, `{}`, `{"source":"manual-approval","expiresAt":"2026-10-05T12:00:00Z","checkedAt":"2026-10-05T11:00:00Z"}`} {
		injected := strings.Replace(string(raw), `"id":"sandbox-local"`, `"agentCertificate":`+field+`,"id":"sandbox-local"`, 1)
		if injected == string(raw) {
			t.Fatal("fixture role not found")
		}
		if _, err = ValidateFrame([]byte(injected), time.Now().UTC()); err == nil {
			t.Fatal("endpoint supplied operator certificate metadata")
		}
	}
}
