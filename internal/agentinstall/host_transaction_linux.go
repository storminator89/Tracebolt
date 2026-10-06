//go:build linux

package agentinstall

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/enrollmentclient"
	"os"
	"path/filepath"
	"strconv"
)

type fileChange struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
	Backup string `json:"backup"`
	Mode   uint32 `json:"mode"`
}
type installJournal struct {
	EnabledBefore    bool         `json:"enabledBefore"`
	AccountAttempted bool         `json:"accountAttempted"`
	AccountConfirmed bool         `json:"accountConfirmed"`
	ID               string       `json:"id"`
	Version          string       `json:"version"`
	Action           Action       `json:"action"`
	Phase            string       `json:"phase"`
	Operation        Operation    `json:"operation"`
	Changes          []fileChange `json:"changes"`
	UID              int          `json:"uid"`
	GID              int          `json:"gid"`
}
type linuxTransaction struct {
	h                                                         *linuxHost
	lock                                                      *os.File
	dir                                                       string
	r                                                         Request
	j                                                         installJournal
	inputs                                                    *VerifiedInputs
	bootstrap                                                 []byte
	staged                                                    string
	account                                                   accountRecord
	installationVersion, profile                              string
	stopped, started, enabled, disabled, published, committed bool
	validated                                                 bool
}

func (t *linuxTransaction) Inspect(ctx context.Context, r Request) (HostFacts, error) {
	return (&LinuxBackend{t.h}).Inspect(ctx, r)
}
func (t *linuxTransaction) Before(ctx context.Context, op Operation) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	t.j.Operation = op
	t.j.Phase = "intent"
	return t.save()
}
func (t *linuxTransaction) Done(ctx context.Context, op Operation) error {
	if op != t.j.Operation {
		return ErrState
	}
	t.j.Phase = "done"
	return t.save()
}
func (t *linuxTransaction) save() error {
	return writePrivateAtomic(filepath.Join(t.dir, "transaction.json"), encode(t.j), 0600)
}
func writePrivateAtomic(path string, raw []byte, mode os.FileMode) error {
	// The caller has established a trusted directory. Never replace a collision at
	// the temporary path or follow a leaf link; uncertain leftovers fail closed.
	temp := path + ".new"
	fd, e := unix.Open(temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(fd), "installer-private-write")
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(temp)
		}
	}()
	if _, e = f.Write(raw); e != nil {
		return ErrState
	}
	if f.Chmod(mode) != nil || f.Sync() != nil || f.Close() != nil {
		return ErrState
	}
	if os.Rename(temp, path) != nil {
		return ErrState
	}
	ok = true
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return ErrState
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrState
	}
	return nil
}
func (t *linuxTransaction) Close() error {
	if t.inputs != nil {
		t.inputs.Close()
	}
	clear(t.bootstrap)
	if t.lock != nil {
		unix.Flock(int(t.lock.Fd()), unix.LOCK_UN)
		return t.lock.Close()
	}
	return nil
}
func (t *linuxTransaction) Apply(ctx context.Context, op Operation, r Request) error {
	if ctx.Err() != nil || op != t.j.Operation || t.j.Phase != "intent" {
		return ErrState
	}
	if t.removedAlready() && (op == OpStop || op == OpDisable || op == OpRemove) {
		return nil
	}
	switch op {
	case OpPrepare:
		return t.prepare(ctx)
	case OpStage:
		return t.stage(ctx)
	case OpEnroll:
		if t.staged == "" || t.account.UID <= 0 {
			return ErrState
		}
		args := []string{"--bootstrap", t.h.path(BootstrapPath), "--state-directory", t.h.path(EnrollmentDirectory)}
		if t.installationVersion == pendingInstallationVersion {
			args = append(args, "--claim-only")
		}
		if r.InsecureHTTPTest {
			args = append(args, "--insecure-http-test")
		}
		return t.h.run(ctx, filepath.Join(t.staged, "enroll-agent"), args, &t.account, true)
	case OpStop:
		if e := t.systemctl(ctx, "stop", UnitName); e != nil {
			return e
		}
		t.stopped = true
		// is-active succeeds only for an active unit. Require the explicit inactive
		// property, rather than treating an arbitrary command failure as drained.
		return t.systemctl(ctx, "verify-stopped", UnitName)
	case OpValidate:
		if t.account.UID == 0 {
			a, ok, e := t.h.account()
			if e != nil || !ok {
				return ErrState
			}
			t.account = a
		}
		if t.installationVersion == pendingInstallationVersion {
			binary := t.h.path(EnrollPath)
			if t.staged != "" {
				binary = filepath.Join(t.staged, "enroll-agent")
			}
			args := []string{"--bootstrap", t.h.path(BootstrapPath), "--state-directory", t.h.path(EnrollmentDirectory), "--validate-service", "--service-identity", strconv.Itoa(t.account.UID) + ":" + strconv.Itoa(t.account.GID)}
			if t.profile == "http-test" {
				args = append(args, "--insecure-http-test")
			}
			if e := t.h.run(ctx, binary, args, &t.account, false); e != nil {
				return e
			}
			t.validated = true
			return nil
		}
		binary := t.h.path(AgentPath)
		if t.staged != "" {
			binary = filepath.Join(t.staged, "lan-agent")
		}
		if e := t.h.run(ctx, binary, []string{"--config", t.h.path(ConfigPath), "--validate-guided"}, &t.account, false); e != nil {
			return e
		}
		t.validated = true
		return nil
	case OpResetRestartState:
		// Deliberate owned restart is separate from automatic crash recovery.
		// All manual starts count toward systemd's unchanged 5/300s limit.
		// Reset only after this transaction stopped and validated retained state.
		if r.Action != Restart || t.r.Action != Restart || !t.stopped || !t.validated {
			return ErrState
		}
		return t.systemctl(ctx, "reset-failed", UnitName)
	case OpPublish:
		return t.publish(ctx)
	case OpStart:
		if e := t.systemctl(ctx, "daemon-reload"); e != nil {
			return e
		}
		if t.r.Action == Install || t.j.EnabledBefore {
			t.enabled = true
			if e := t.systemctl(ctx, "enable", UnitName); e != nil {
				return e
			}
		}
		// Treat an uncertain start as potentially running during rollback.
		t.started = true
		if e := t.systemctl(ctx, "start", UnitName); e != nil {
			return e
		}
		return t.systemctl(ctx, "verify-active", UnitName)
	case OpDisable:
		t.disabled = true
		return t.systemctl(ctx, "disable", UnitName)
	case OpRemove:
		return t.remove(ctx)
	}
	return ErrContract
}
func (t *linuxTransaction) systemctl(ctx context.Context, args ...string) error {
	c, cancel := operationTimeout(ctx)
	defer cancel()
	return t.h.run(c, t.h.path(systemctlPath), args, nil, false)
}
func (t *linuxTransaction) prepare(ctx context.Context) error {
	if t.r.Resume {
		owned, e := t.h.readOwnership()
		if e != nil || t.h.validateRetained(owned) != nil {
			return ErrState
		}
		t.account = accountRecord{owned.Installation.UID, owned.Installation.GID}
		return nil
	}

	if _, ok, e := t.h.account(); e != nil || ok {
		return ErrState
	}

	_, b, e := readBootstrap(ctx, t.r.BootstrapFile, t.r.BootstrapSHA256)
	if e != nil {
		return e
	}
	t.j.AccountAttempted = true
	if t.save() != nil {
		return ErrState
	}
	runErr := t.h.run(ctx, t.h.path(useraddPath), []string{"--system", "--user-group", "--no-create-home", "--home-dir", StateDirectory, "--shell", nologinPath, Account}, nil, false)
	// Even a failed/cancelled process may have created its account. Reconcile the
	// exact read-only local identity; never delete it or claim absence on error.
	a, ok, readErr := t.h.account()
	if readErr != nil || !ok {
		return ErrState
	}
	t.account = a
	t.j.UID = a.UID
	t.j.GID = a.GID
	m := installation{Version: t.installationVersion, UID: a.UID, GID: a.GID, Profile: b.Profile, AgentHash: t.r.AgentSHA256, EnrollHash: t.r.EnrollSHA256, SourceHash: t.r.SourceSHA256, BootstrapHash: t.r.BootstrapSHA256, UnitHash: sum([]byte(unitForMode(t.account, t.installationVersion, t.profile)))}
	if t.createOwnership(m) != nil {
		return ErrState
	}
	t.j.AccountConfirmed = true
	if t.save() != nil {
		return ErrState
	}
	if runErr != nil || ctx.Err() != nil {
		return ErrOperation
	}
	for _, p := range []string{InstallDirectory, publicDirectory} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := t.h.createPublicDirectory(t.h.path(p)); e != nil {
			return ErrState
		}
	}
	if os.Mkdir(t.h.path(StateDirectory), 0700) != nil {
		return ErrState
	}
	if os.Chown(t.h.path(StateDirectory), a.UID, a.GID) != nil {
		return ErrState
	}
	// Bootstrap is public only. Verify the protected copy again before publishing;
	// root never opens endpoint keys or reads invitation input.
	temp := filepath.Join(t.dir, "bootstrap-"+t.j.ID+".json")
	if e := exclusiveBytes(temp, t.bootstrap, 0644); e != nil {
		return e
	}
	b, e = enrollmentclient.LoadBootstrap(temp)
	if e != nil || b.Profile != "tls" && b.Profile != "http-test" || sum(t.bootstrap) != t.r.BootstrapSHA256 {
		return ErrState
	}
	if e := exclusiveBytes(t.h.path(BootstrapPath), t.bootstrap, 0644); e != nil {
		return e
	}
	return t.markPrepared()
}
func exclusiveBytes(path string, raw []byte, mode os.FileMode) error {
	fd, e := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(fd), "installer-new-file")
	defer f.Close()
	if _, e = f.Write(raw); e != nil {
		return ErrState
	}
	if f.Chmod(mode) != nil || f.Sync() != nil {
		return ErrState
	}
	return syncDirectory(filepath.Dir(path))
}
func (t *linuxTransaction) stage(ctx context.Context) error {
	if t.inputs == nil {
		return ErrArtifact
	}
	// Stable fixed basename in a root-owned directory; never execute a user path.
	t.staged = filepath.Join(t.h.path(InstallDirectory), ".staging-"+t.j.ID)
	if t.h.createPublicDirectory(t.staged) != nil {
		return ErrState
	}
	for _, a := range []*VerifiedArtifact{t.inputs.Agent, t.inputs.Enrollment} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dest := filepath.Join(t.staged, string(a.Role()))
		fd, e := unix.Open(dest, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return ErrArtifact
		}
		f := os.NewFile(uintptr(fd), "installer-staged-artifact")
		e = a.CopyVerified(ctx, f)
		if e == nil {
			e = f.Sync()
		}
		if closeErr := f.Close(); e == nil {
			e = closeErr
		}
		if e != nil {
			return ErrArtifact
		}
		// Final immutable staging snapshot must itself match BOTH hash and role.
		check, e := VerifyBinary(ctx, dest, a.SHA256(), a.Role())
		if e != nil {
			return e
		}
		check.Close()
		if os.Chmod(dest, 0555) != nil {
			return ErrState
		}
	}
	return syncDirectory(t.staged)
}
func (t *linuxTransaction) recordChange(path, after string, mode os.FileMode) (fileChange, error) {
	c := fileChange{Path: path, After: after, Mode: uint32(mode)}
	actual := t.h.path(path)
	info, e := os.Lstat(actual)
	if e == nil {
		if t.h.secureFile(actual, false, MaxBinaryBytes) != nil {
			return c, ErrState
		}
		raw, e := os.ReadFile(actual)
		if e != nil {
			return c, ErrState
		}
		c.Before = sum(raw)
		c.Mode = uint32(info.Mode().Perm())
		c.Backup = filepath.Join(t.dir, "backup-"+t.j.ID+"-"+strconv.Itoa(len(t.j.Changes)))
		if e = exclusiveBytes(c.Backup, raw, 0600); e != nil {
			return c, e
		}
	} else if !os.IsNotExist(e) {
		return c, ErrState
	}
	t.j.Changes = append(t.j.Changes, c)
	if t.save() != nil {
		return c, ErrState
	}
	return c, nil
}
func (t *linuxTransaction) changeBytes(path string, raw []byte, mode os.FileMode) error {
	c, e := t.recordChange(path, sum(raw), mode)
	if e != nil {
		return e
	}
	if e = writePrivateAtomic(t.h.path(path), raw, mode); e != nil {
		return e
	}
	actual, e := os.ReadFile(t.h.path(path))
	if e != nil || sum(actual) != c.After {
		return ErrState
	}
	return nil
}
func (t *linuxTransaction) publish(ctx context.Context) error {
	if t.staged == "" || t.inputs == nil {
		return ErrState
	}
	m := installation{Version: t.installationVersion, UID: t.account.UID, GID: t.account.GID, AgentHash: t.r.AgentSHA256, EnrollHash: t.r.EnrollSHA256, SourceHash: t.r.SourceSHA256, UnitHash: sum([]byte(unitForMode(t.account, t.installationVersion, t.profile))), BootstrapHash: t.r.BootstrapSHA256}
	if t.r.Action == Upgrade {
		old, e := t.h.readInstallation()
		if e != nil {
			return e
		}
		m.UID = old.UID
		m.GID = old.GID
		m.Profile = old.Profile
		m.BootstrapHash = old.BootstrapHash
	} else {
		_, b, e := readBootstrap(ctx, t.h.path(BootstrapPath), t.r.BootstrapSHA256)
		if e != nil {
			return e
		}
		m.Profile = b.Profile
	}
	for _, a := range []*VerifiedArtifact{t.inputs.Agent, t.inputs.Enrollment} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, e := os.ReadFile(filepath.Join(t.staged, string(a.Role())))
		if e != nil || sum(raw) != a.SHA256() {
			return ErrArtifact
		}
		if e = t.changeBytes(InstallDirectory+"/"+string(a.Role()), raw, 0555); e != nil {
			return e
		}
	}
	if e := t.changeBytes(UnitPath, []byte(unitForMode(t.account, t.installationVersion, t.profile)), 0644); e != nil {
		return e
	}
	if e := t.changeBytes(ManifestPath, encode(m), 0644); e != nil {
		return e
	}
	t.published = true
	if e := t.updateOwnership("installed", m); e != nil {
		return e
	}
	return t.h.validateInstallation(ctx, m)
}
func (t *linuxTransaction) remove(ctx context.Context) error {
	m, e := t.h.readInstallation()
	if e != nil || t.h.validateInstallation(ctx, m) != nil {
		return ErrState
	}
	for _, p := range []string{UnitPath, AgentPath, EnrollPath, ManifestPath} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, e = t.recordChange(p, "", 0); e != nil {
			return e
		}
		if os.Remove(t.h.path(p)) != nil || syncDirectory(filepath.Dir(t.h.path(p))) != nil {
			return ErrState
		}
	}
	if e := t.updateOwnership("uninstalled", m); e != nil {
		return e
	}
	return t.systemctl(ctx, "daemon-reload")
}
func (t *linuxTransaction) Commit(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	t.j.Phase = "committed"
	if e := t.save(); e != nil {
		return e
	}
	t.committed = true
	if e := t.cleanupOwnedTemporary(); e != nil {
		return e
	}
	// Keep the complete, bounded journal for administrative audit/recovery. Future
	// operations archive only this validated completed record while holding lock.
	return t.finishJournal("last-committed.json")
}
func (t *linuxTransaction) finishJournal(name string) error {
	dest := filepath.Join(t.dir, name)
	if _, e := os.Lstat(dest); e == nil {
		if t.h.secureFile(dest, true, 64<<10) != nil {
			return ErrState
		}
	} else if !os.IsNotExist(e) {
		return ErrState
	}
	if os.Rename(filepath.Join(t.dir, "transaction.json"), dest) != nil {
		return ErrState
	}
	return syncDirectory(t.dir)
}
func (t *linuxTransaction) Rollback(ctx context.Context) error {
	if t.j.AccountAttempted {
		owned, e := t.h.readOwnership()
		if !t.j.AccountConfirmed || e != nil || owned.Status == "preparing" {
			return ErrState
		}
	}
	if t.committed {
		return ErrState
	} // nil must mean a genuine rollback, not a reconciled commit.
	raw, e := os.ReadFile(filepath.Join(t.dir, "transaction.json"))
	if e != nil {
		return ErrState
	}
	var disk installJournal
	if decodeCanonical(raw, &disk) != nil || disk.Version != t.j.Version {
		return ErrState
	}
	if disk.Phase == "committed" {
		return ErrState
	}
	if t.started {
		if t.systemctl(ctx, "stop", UnitName) != nil || t.systemctl(ctx, "verify-stopped", UnitName) != nil {
			return ErrState
		}
	}
	if t.enabled && t.r.Action == Install {
		if t.systemctl(ctx, "disable", UnitName) != nil {
			return ErrState
		}
	}
	for n := len(t.j.Changes) - 1; n >= 0; n-- {
		c := t.j.Changes[n]
		path := t.h.path(c.Path)
		raw, e := os.ReadFile(path)
		if e == nil && sum(raw) != c.After && sum(raw) != c.Before {
			return ErrState
		}
		if e != nil && !os.IsNotExist(e) {
			return ErrState
		}
		if c.Before != "" {
			backup, e := os.ReadFile(c.Backup)
			if e != nil || sum(backup) != c.Before {
				return ErrState
			}
			if e = writePrivateAtomic(path, backup, os.FileMode(c.Mode)); e != nil {
				return e
			}
		} else if e == nil {
			if os.Remove(path) != nil || syncDirectory(filepath.Dir(path)) != nil {
				return ErrState
			}
		}
	}
	if t.stopped || t.started || t.disabled || t.published {
		if t.systemctl(ctx, "daemon-reload") != nil {
			return ErrState
		}
		if t.r.Action != Install && (t.enabled || t.disabled) {
			action := "disable"
			if t.j.EnabledBefore {
				action = "enable"
			}
			if t.systemctl(ctx, action, UnitName) != nil {
				return ErrState
			}
		}
		// Do not automatically restart a service after failed state validation.
		// Identity/data/account remain untouched; explicit restart revalidates them.
	}
	if e := t.cleanupOwnedTemporary(); e != nil {
		return e
	}
	t.j.Phase = "rolled-back"
	if t.save() != nil {
		return ErrState
	}
	return t.finishJournal("last-rollback.json")
}

// Ensure diagnostics cannot recursively display artifact handles or public paths.
func (linuxTransaction) String() string               { return "agentinstall.Transaction{privateState:redacted}" }
func (t linuxTransaction) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }
func (linuxTransaction) MarshalJSON() ([]byte, error) {
	return []byte(`{"privateStateRedacted":true}`), nil
}

func (t *linuxTransaction) cleanupOwnedTemporary() error {
	// Only this transaction's exact hashed regular files, never identity, account,
	// directories supplied by the operator or an unvalidated crash ledger.
	remove := func(path, digest string) error {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			return nil
		}
		if t.h.secureFile(path, false, MaxBinaryBytes) != nil {
			return ErrState
		}
		raw, e := os.ReadFile(path)
		if e != nil || sum(raw) != digest {
			return ErrState
		}
		if os.Remove(path) != nil {
			return ErrState
		}
		return syncDirectory(filepath.Dir(path))
	}
	for _, c := range t.j.Changes {
		if c.Backup != "" {
			if remove(c.Backup, c.Before) != nil {
				return ErrState
			}
		}
	}
	if t.staged != "" {
		if t.h.secureDirectory(t.staged, false) != nil {
			return ErrState
		}
		for _, a := range []*VerifiedArtifact{t.inputs.Agent, t.inputs.Enrollment} {
			if remove(filepath.Join(t.staged, string(a.Role())), a.SHA256()) != nil {
				return ErrState
			}
		}
		if os.Remove(t.staged) != nil || syncDirectory(filepath.Dir(t.staged)) != nil {
			return ErrState
		}
	}
	if len(t.bootstrap) > 0 {
		if remove(filepath.Join(t.dir, "bootstrap-"+t.j.ID+".json"), sum(t.bootstrap)) != nil {
			return ErrState
		}
	}
	return nil
}
func unitFor(a accountRecord) string {
	unit, e := UnitForAccount(a.UID, a.GID)
	if e != nil {
		return ""
	}
	return unit
}

func unitForMode(a accountRecord, version, profile string) string {
	if version == readyInstallationVersion {
		return unitFor(a)
	}
	if version != pendingInstallationVersion {
		return ""
	}
	unit, err := PendingUnitForAccount(a.UID, a.GID, profile)
	if err != nil {
		return ""
	}
	return unit
}
