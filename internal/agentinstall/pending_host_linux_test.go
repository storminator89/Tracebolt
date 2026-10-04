//go:build linux

package agentinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pendingInstallerFixture(t *testing.T) (Request, *LinuxBackend, *[]string) {
	r, b, events := installerHostFixture(t)
	r.PendingService = true
	old := b.host.run
	b.host.run = func(ctx context.Context, path string, args []string, a *accountRecord, interactive bool) error {
		if filepath.Base(path) == "enroll-agent" && strings.Contains(strings.Join(args, " "), "--validate-service") {
			*events = append(*events, "validate-service:"+strings.Join(args, " "))
			if interactive || a == nil || !strings.Contains(strings.Join(args, " "), "--service-identity ") {
				t.Fatal("offline validation identity contract")
			}
			_, e := os.Stat(filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel"))
			return e
		}
		if filepath.Base(path) == "enroll-agent" && interactive && !strings.Contains(strings.Join(args, " "), "--claim-only") {
			t.Fatal("pending install waited in terminal")
		}
		return old(ctx, path, args, a, interactive)
	}
	return r, b, events
}
func TestPendingInstallerVersionedLifecycleAndNoModeConversion(t *testing.T) {
	r, b, events := pendingInstallerFixture(t)
	out, e := Execute(context.Background(), r, b)
	if e != nil || !out.Committed {
		t.Fatal("pending install", e, out.FailureStage)
	}
	m, e := b.host.readInstallation()
	o, oe := b.host.readOwnership()
	if e != nil || oe != nil || m.Version != pendingInstallationVersion || o.Version != pendingOwnershipVersion {
		t.Fatal("mode not durably versioned")
	}
	unit, _ := os.ReadFile(b.host.path(UnitPath))
	if !strings.Contains(string(unit), "--enrollment-bootstrap") || strings.Contains(string(unit), "ConditionPathExists=") {
		t.Fatal("pending unit not published")
	}
	joined := strings.Join(*events, "\n")
	if strings.Index(joined, "--claim-only") < 0 || strings.Index(joined, "validate-service:") < strings.Index(joined, "--claim-only") || strings.Index(joined, "systemctl:start") < strings.Index(joined, "validate-service:") {
		t.Fatal("claim/validate/start ordering")
	}
	r.PendingService = false
	for _, action := range []Action{Restart, Upgrade, Uninstall} {
		r.Action = action
		if out, e = Execute(context.Background(), r, b); e != nil || !out.Committed {
			t.Fatal("pending lifecycle", action, e, out.FailureStage)
		}
	}
	r.Action = Install
	r.Resume = true
	if _, e = Execute(context.Background(), r, b); e == nil {
		t.Fatal("pending retained state adopted as v1")
	}
	r.PendingService = true
	if out, e = Execute(context.Background(), r, b); e != nil || !out.Committed {
		t.Fatal("same-mode resume", e, out.FailureStage)
	}
}
func TestPendingInstallerUncertainClaimNeverPublishesService(t *testing.T) {
	r, b, events := pendingInstallerFixture(t)
	old := b.host.run
	b.host.run = func(ctx context.Context, path string, args []string, a *accountRecord, interactive bool) error {
		if filepath.Base(path) == "enroll-agent" && interactive {
			if e := old(ctx, path, args, a, interactive); e != nil {
				return e
			}
			return ErrOperation
		}
		return old(ctx, path, args, a, interactive)
	}
	out, e := Execute(context.Background(), r, b)
	if e == nil || out.Committed || out.FailureStage != OpEnroll {
		t.Fatal("uncertain claim committed installation")
	}
	if _, e = os.Stat(b.host.path(UnitPath)); !os.IsNotExist(e) {
		t.Fatal("uncertain claim published unit")
	}
	if strings.Contains(strings.Join(*events, "\n"), "systemctl:start") {
		t.Fatal("uncertain claim started service")
	}
	o, e := b.host.readOwnership()
	if e != nil || o.Status != "prepared" || o.Version != pendingOwnershipVersion {
		t.Fatal("retained v2 identity not preserved")
	}
	if _, e = os.Stat(filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel")); e != nil {
		t.Fatal("claim identity deleted")
	}
}
func TestPendingInstallerCanceledStartStopsAndRetainsIdentity(t *testing.T) {
	r, b, events := pendingInstallerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := b.host.run
	b.host.run = func(c context.Context, path string, args []string, a *accountRecord, interactive bool) error {
		e := old(c, path, args, a, interactive)
		if filepath.Base(path) == "systemctl" && len(args) > 0 && args[0] == "start" {
			cancel()
			return context.Canceled
		}
		return e
	}
	out, e := Execute(ctx, r, b)
	if e == nil || out.Committed {
		t.Fatal("canceled start committed")
	}
	joined := strings.Join(*events, "\n")
	if !strings.Contains(joined, "systemctl:stop "+UnitName) || !strings.Contains(joined, "systemctl:verify-stopped "+UnitName) {
		t.Fatal("uncertain start not drained")
	}
	if _, e = os.Stat(filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel")); e != nil {
		t.Fatal("cancel deleted identity")
	}
}
