//go:build linux

package agentinstall

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadAdminCoordinatorLeavesServiceStopped(t *testing.T) {
	r, f := installFixture()
	r.Action = Upgrade
	r.UpgradeCoordinatorFD = 7
	f.facts.InstallationOwned = true
	out, err := Execute(context.Background(), r, f)
	if err != nil || !out.Committed || !out.ServiceLeftStopped || !out.IdentityRetained {
		t.Fatal("coordinated upgrade failed", err)
	}
	for _, event := range f.events {
		if event == "apply:"+string(OpStart) || event == "apply:"+string(OpEnroll) || event == "apply:"+string(OpPrepare) {
			t.Fatal("coordinator seam started/enrolled", event)
		}
	}
	for _, action := range []Action{Install, Restart, Uninstall} {
		r.Action = action
		if _, err := BuildPlan(r, f.facts); err == nil {
			t.Fatal("borrowed lock accepted outside upgrade", action)
		}
	}
	r.Action = Upgrade
	r.Apply = false
	if _, err := BuildPlan(r, f.facts); err == nil {
		t.Fatal("borrowed lock accepted in dry run")
	}
}

func TestReadAdminBorrowedLockRetainsExclusionAfterNativeClose(t *testing.T) {
	h := &linuxHost{root: t.TempDir(), owner: os.Geteuid()}
	dir := h.path(controlDirectory)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{readAdminIntent: []byte(`{"fixture":"completed-original"}`), ownershipPath: []byte("original owner fixture")} {
		if err := os.WriteFile(h.path(path), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	lockPath := filepath.Join(dir, "install.lock")
	parent, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err = unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	r := Request{Action: Upgrade, Apply: true, UpgradeCoordinatorFD: int(parent.Fd()), AgentSHA256: strings.Repeat("a", 64), EnrollSHA256: strings.Repeat("b", 64), SourceSHA256: strings.Repeat("c", 64)}
	intent := readAdminUpgradeIntentRecord{Version: "tracebolt.read-admin-upgrade-transaction.v1", Phase: "native-ready", AgentSHA256: r.AgentSHA256, EnrollSHA256: r.EnrollSHA256, SourceSHA256: r.SourceSHA256, PreviousOwnerSHA256: sum([]byte("original owner fixture")), HistorySHA256: strings.Repeat("d", 64)}
	if err = os.WriteFile(h.path(readAdminUpgradeIntent), encode(intent), 0600); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(parent.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unix.FcntlInt(parent.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err = h.readAdminUpgradeGuard(r); err != nil {
		t.Fatal("valid borrowed lock rejected", err)
	}
	flagsAfter, err := unix.FcntlInt(parent.Fd(), unix.F_GETFD, 0)
	if err != nil || flagsAfter != flags|unix.FD_CLOEXEC {
		t.Fatal("borrowed flags not preserved with CLOEXEC")
	}
	child := exec.Command(os.Args[0], "-test.run=^TestReadAdminValidationChildDoesNotInheritLock$")
	child.Env = append(os.Environ(), "TRACEBOLT_INERT_BORROWED_FD="+strconv.Itoa(int(parent.Fd())), "TRACEBOLT_INERT_BORROWED_PATH="+lockPath)
	if err = child.Run(); err != nil {
		t.Fatal("validation child inherited installer lock")
	}
	competitor, err := os.OpenFile(lockPath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer competitor.Close()
	excluded := func() {
		t.Helper()
		if err := unix.Flock(int(competitor.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			t.Fatal("competing installer entered")
		}
	}
	excluded()
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	tx := &linuxTransaction{lock: os.NewFile(uintptr(fd), "borrowed-fixture"), borrowedLock: true}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	excluded()
	bad := r
	bad.UpgradeCoordinatorFD = int(competitor.Fd())
	if h.readAdminUpgradeGuard(bad) == nil {
		t.Fatal("unshared competing descriptor accepted")
	}
	bad = r
	bad.AgentSHA256 = strings.Repeat("e", 64)
	if h.readAdminUpgradeGuard(bad) == nil {
		t.Fatal("different release accepted")
	}
	bad = r
	bad.UpgradeCoordinatorFD = 0
	for _, action := range []Action{Install, Upgrade, Restart, Uninstall} {
		bad.Action = action
		if h.readAdminUpgradeGuard(bad) == nil {
			t.Fatal("ordinary operation bypassed unresolved upgrade", action)
		}
	}
	if err = unix.Flock(int(parent.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(competitor.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("parent unlock did not release", err)
	}
}

func TestOrdinaryUpgradeRejectsCompletedReadAdmin(t *testing.T) {
	h := &linuxHost{root: t.TempDir(), owner: os.Geteuid()}
	if err := os.MkdirAll(h.path(controlDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path(readAdminIntent), []byte("retained receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	if h.readAdminUpgradeGuard(Request{Action: Upgrade}) == nil {
		t.Fatal("ordinary upgrade would break helper binding")
	}
	if err := h.readAdminUpgradeGuard(Request{Action: Restart}); err != nil {
		t.Fatal("ordinary completed restart blocked", err)
	}
}

func TestReadAdminNativeTransactionKeepsCoordinatorLockAtEveryOperation(t *testing.T) {
	r, b, events := installerHostFixture(t)
	if out, err := Execute(context.Background(), r, b); err != nil || !out.Committed {
		t.Fatal("fixture install", err)
	}
	if err := os.WriteFile(b.host.path(readAdminIntent), []byte(`{"fixture":"completed-v2"}`), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := os.ReadFile(b.host.path(ownershipPath))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.OpenFile(filepath.Join(b.host.path(controlDirectory), "install.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err = unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	r.Action = Upgrade
	r.UpgradeCoordinatorFD = int(parent.Fd())
	marker := readAdminUpgradeIntentRecord{Version: "tracebolt.read-admin-upgrade-transaction.v1", Phase: "native-ready", AgentSHA256: r.AgentSHA256, EnrollSHA256: r.EnrollSHA256, SourceSHA256: r.SourceSHA256, PreviousOwnerSHA256: sum(owner), HistorySHA256: strings.Repeat("a", 64)}
	if err = os.WriteFile(b.host.path(readAdminUpgradeIntent), encode(marker), 0600); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(filepath.Join(b.host.path(controlDirectory), "install.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	excluded := func() {
		t.Helper()
		if unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
			t.Fatal("competing installer entered coordinated transaction")
		}
	}
	originalRun := b.host.run
	checks := 0
	b.host.run = func(ctx context.Context, path string, args []string, a *accountRecord, interactive bool) error {
		excluded()
		checks++
		if filepath.Base(path) == "systemctl" && len(args) > 0 && (args[0] == "start" || args[0] == "enable") {
			t.Fatal("premature native restart")
		}
		return originalRun(ctx, path, args, a, interactive)
	}
	before := len(*events)
	out, err := Execute(context.Background(), r, b)
	if err != nil || !out.Committed || !out.ServiceLeftStopped || checks == 0 {
		t.Fatal("native handoff", err, out.FailureStage)
	}
	excluded()
	for _, event := range (*events)[before:] {
		if strings.HasPrefix(event, "enroll-agent:") {
			t.Fatal("upgrade re-enrolled")
		}
	}
	sentinel, err := os.ReadFile(filepath.Join(b.host.path(EnrollmentDirectory), "identity-sentinel"))
	if err != nil || string(sentinel) != "retained identity fixture" {
		t.Fatal("identity changed")
	}
}

func TestReadAdminValidationChildDoesNotInheritLock(t *testing.T) {
	fd := os.Getenv("TRACEBOLT_INERT_BORROWED_FD")
	if fd == "" {
		t.Skip("inert child probe only")
	}
	if _, err := strconv.Atoi(fd); err != nil {
		t.Fatal("invalid inert descriptor")
	}
	target, err := os.Readlink("/proc/self/fd/" + fd)
	if err == nil && target == os.Getenv("TRACEBOLT_INERT_BORROWED_PATH") {
		t.Fatal("borrowed coordinator descriptor escaped to validation child")
	}
}
