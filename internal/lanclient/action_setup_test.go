package lanclient

import (
	"context"
	"localrmm/internal/actionpermit"
	"testing"
)

func TestActionSetupReadinessOnlyCapabilities(t *testing.T) {
	f := serviceActionTestFixture(t)
	read := func(string) (Material, uint32, uint32, error) { return f.s.material, 1234, 1234, nil }
	got, err := checkActionSetupReadiness(context.Background(), "/fixture/agent.json", read, f.s.local, f.helper.Capabilities, f.s.now)
	if err != nil || got.SchemaVersion != ActionSetupReadinessVersion || got.Identity.SenderBinding != f.s.material.binding || got.Capabilities.RootPolicyDigest != f.local.policy.RootPolicyDigest {
		t.Fatal(got, err)
	}
	if f.helper.calls != 1 || f.helper.submits != 0 || f.helper.statuses != 0 || f.network != 0 {
		t.Fatal("readiness performed non-capabilities I/O")
	}
}

func TestActionSetupReadinessRejectsGrantOrCurrentIdentityChanges(t *testing.T) {
	for _, kind := range []string{"absent", "disabled", "identity", "grant_changed", "config_changed", "capability_mismatch", "helper_disabled", "stale"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionTestFixture(t)
			reads := 0
			read := func(string) (Material, uint32, uint32, error) {
				reads++
				m := f.s.material
				if kind == "config_changed" && reads > 1 {
					m.config.ManagerOrigin = "https://changed.test"
				}
				return m, 1234, 1234, nil
			}
			switch kind {
			case "absent":
				f.localError = errActionDisabled
			case "disabled":
				f.local.policy.Enabled = false
			case "identity":
				f.local.policy.AgentGID = 1235
			case "grant_changed":
				f.helper.capHook = func(int) { f.local.revision = actionpermit.Digest([]byte("changed")) }
			case "capability_mismatch":
				f.helper.caps.KeyID = actionpermit.Digest(nil)
			case "helper_disabled":
				f.helper.caps.Enabled = false
			case "stale":
				f.helper.caps.CapturedAt -= 3600
			}
			if _, err := checkActionSetupReadiness(context.Background(), "/fixture", read, f.s.local, f.helper.Capabilities, f.s.now); err == nil {
				t.Fatal("accepted", kind)
			}
			if (kind == "absent" || kind == "disabled" || kind == "identity") && f.helper.calls != 0 {
				t.Fatal("contacted helper before validating actual grant")
			}
			if f.helper.submits != 0 || f.helper.statuses != 0 || f.network != 0 {
				t.Fatal("readiness performed non-capabilities I/O")
			}
		})
	}
}
