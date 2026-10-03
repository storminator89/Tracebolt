package security_test

import (
	"context"
	"localrmm/internal/agentinstall"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// These tests intentionally use only trusted-facts/in-memory fixtures. The
// production LinuxBackend must not be invoked to simulate account or service
// operations; its unexported OS seams are covered by disposable internal tests.
func TestIndependentAgentInstallRetainedPreparationRequiresExplicitResume(t *testing.T) {
	cases := []struct {
		name                          string
		action                        agentinstall.Action
		resume, prepared, owned, gone bool
		allowed                       bool
	}{
		{"clean-install", agentinstall.Install, false, false, false, false, true},
		{"resume-without-owned-evidence", agentinstall.Install, true, false, false, false, false},
		{"preparation-needs-resume", agentinstall.Install, false, true, false, false, false},
		{"explicit-preparation-resume", agentinstall.Install, true, true, false, false, true},
		{"installed-is-not-preparation", agentinstall.Install, true, false, true, false, false},
		{"removed-needs-resume", agentinstall.Install, false, false, true, true, false},
		{"explicit-removed-resume", agentinstall.Install, true, false, true, true, true},
		{"removed-cannot-upgrade", agentinstall.Upgrade, false, false, true, true, false},
		{"removed-cannot-restart", agentinstall.Restart, false, false, true, true, false},
		{"repeat-owned-uninstall", agentinstall.Uninstall, false, false, true, true, true},
		{"preparation-is-not-installed", agentinstall.Restart, false, true, false, false, false},
		{"resume-does-not-authorize-upgrade", agentinstall.Upgrade, true, false, true, false, false},
		{"resume-does-not-authorize-restart", agentinstall.Restart, true, false, true, false, false},
		{"resume-does-not-authorize-uninstall", agentinstall.Uninstall, true, false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b := installBoundaryFixture(tc.action)
			r.Apply, r.Resume = false, tc.resume
			b.initial.RetainedPreparation = tc.prepared
			b.initial.InstallationOwned = tc.owned
			b.initial.InstallationRemoved = tc.gone
			result, err := agentinstall.Execute(context.Background(), r, b)
			if (err == nil) != tc.allowed {
				t.Fatal("retained-state or explicit-resume scope was misclassified")
			}
			if result.Committed || result.RolledBack || !reflect.DeepEqual(b.events, []string{"inspect"}) {
				t.Fatal("retained-state planning acquired a mutating capability")
			}
		})
	}
}

func TestIndependentAgentInstallGeneratedUnitBindsNumericIdentity(t *testing.T) {
	unit, err := agentinstall.UnitForAccount(1234, 2345)
	if err != nil {
		t.Fatal("valid dedicated numeric identity was rejected")
	}
	for _, directive := range []string{"User=1234\n", "Group=2345\n", " --service-identity 1234:2345\n", "KillMode=control-group\n"} {
		if strings.Count(unit, directive) != 1 {
			t.Fatal("generated unit lost its exact numeric execution or drain contract")
		}
	}
	if strings.Contains(unit, "User="+agentinstall.Account+"\n") || strings.Contains(unit, "Group="+agentinstall.Account+"\n") {
		t.Fatal("generated unit retained an NSS-resolved execution identity")
	}
	for _, id := range []int{0, -1} {
		if _, err := agentinstall.UnitForAccount(id, 2345); err == nil {
			t.Fatal("non-dedicated UID was accepted")
		}
		if _, err := agentinstall.UnitForAccount(1234, id); err == nil {
			t.Fatal("non-dedicated GID was accepted")
		}
	}
	if strconv.IntSize == 64 {
		for _, value := range []uint64{1<<32 - 1, 1 << 32, 1<<32 + 1234} {
			id := int(value)
			if _, err := agentinstall.UnitForAccount(id, 2345); err == nil {
				t.Fatal("reserved or truncating UID was accepted")
			}
			if _, err := agentinstall.UnitForAccount(1234, id); err == nil {
				t.Fatal("reserved or truncating GID was accepted")
			}
		}
	}
}

func TestIndependentAgentInstallResumeRechecksRetainedEvidenceUnderLock(t *testing.T) {
	for _, retained := range []string{"preparation", "removed"} {
		t.Run(retained, func(t *testing.T) {
			r, b := installBoundaryFixture(agentinstall.Install)
			r.Resume = true
			if retained == "preparation" {
				b.initial.RetainedPreparation = true
			} else {
				b.initial.InstallationOwned = true
				b.initial.InstallationRemoved = true
			}
			// Ownership evidence disappears between read-only preflight and the
			// locked recheck. A name or stale prior fact must not authorize reuse.
			b.locked.RetainedPreparation = false
			b.locked.InstallationOwned = false
			b.locked.InstallationRemoved = false
			result, err := agentinstall.Execute(context.Background(), r, b)
			if err != agentinstall.ErrOperation || result.Committed || !result.RolledBack ||
				!reflect.DeepEqual(b.events, []string{"inspect", "begin", "inspect_locked", "rollback", "close"}) {
				t.Fatal("resume reused stale pre-lock installation ownership")
			}
		})
	}
}
