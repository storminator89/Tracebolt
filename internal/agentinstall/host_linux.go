//go:build linux

package agentinstall

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const controlDirectory = "/var/lib/tracebolt-agent-installer"
const publicDirectory = "/etc/tracebolt-agent"
const systemctlPath = "/usr/bin/systemctl"
const useraddPath = "/usr/sbin/useradd"
const nologinPath = "/usr/sbin/nologin"

// LinuxBackend has no configurable destination, shell, command or account. Its
// real operations require explicit apply, root and a running systemd instance.
// Constructing it and Inspect are read-only. Tests use private inert hooks.
type LinuxBackend struct{ host *linuxHost }
type linuxHost struct {
	root     string // empty in production; unexported disposable fixture seam
	owner    int
	systemd  func() bool
	unit     func(context.Context) (unitStatus, error)
	terminal func() bool
	account  func() (accountRecord, bool, error)
	run      func(context.Context, string, []string, *accountRecord, bool) error
}
type accountRecord struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}
type installation struct {
	Version       string `json:"version"`
	Profile       string `json:"profile"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	AgentHash     string `json:"agentHash"`
	EnrollHash    string `json:"enrollHash"`
	SourceHash    string `json:"sourceHash"`
	BootstrapHash string `json:"bootstrapHash"`
	UnitHash      string `json:"unitHash"`
}

func NewLinuxBackend() *LinuxBackend {
	h := &linuxHost{owner: 0}
	h.systemd = actualSystemd
	h.unit = actualUnitStatus
	h.terminal = terminalReady
	h.account = actualAccount
	h.run = runFixedCommand
	return &LinuxBackend{host: h}
}
func (h *linuxHost) path(p string) string {
	if h.root == "" {
		return p
	}
	return filepath.Join(h.root, p)
}
func (b *LinuxBackend) Inspect(ctx context.Context, r Request) (HostFacts, error) {
	if b == nil || b.host == nil || ctx == nil || ctx.Err() != nil {
		return HostFacts{}, ErrPreflight
	}
	h := b.host
	facts := HostFacts{Linux: true, Root: os.Geteuid() == h.owner, SystemdAvailable: h.systemd(), inspectionStage: "preflight_systemd"}
	if !facts.SystemdAvailable {
		return facts, ErrPreflight
	}
	facts.inspectionStage = "preflight_terminal"
	if r.Action == Install && !h.terminal() {
		return facts, ErrPreflight
	}
	for index, p := range []string{systemctlPath, useraddPath, nologinPath} {
		facts.inspectionStage = []Operation{"preflight_systemctl_tool", "preflight_useradd_tool", "preflight_nologin_tool"}[index]
		if h.secureFile(h.path(p), false, 16<<20) != nil {
			return facts, ErrPreflight
		}
	}
	for index, p := range []string{"/opt", "/etc", "/var/lib", "/etc/systemd/system"} {
		facts.inspectionStage = []Operation{"preflight_opt_directory", "preflight_etc_directory", "preflight_state_directory", "preflight_unit_directory"}[index]
		if h.secureDirectory(h.path(p), false) != nil {
			return facts, ErrPreflight
		}
	}
	facts.inspectionStage = "preflight_unit_status"
	status, ue := h.unit(ctx)
	if ue != nil {
		facts.inspectionStage = checkpointFailureStage(ue, facts.inspectionStage)
		return facts, ErrPreflight
	}
	facts.inspectionStage = "preflight_account"
	acct, exists, e := h.account()
	if e != nil {
		return facts, ErrPreflight
	}
	facts.inspectionStage = "preflight_installation_state"
	manifest, e := h.readInstallation()
	if e == nil {
		if !status.owned() {
			return facts, ErrState
		}
		if !exists || acct.UID != manifest.UID || acct.GID != manifest.GID {
			return facts, ErrState
		}
		owned, oe := h.readOwnership()
		if oe != nil || owned.Status != "installed" || owned.Installation != manifest || h.validateStateDomain(owned) != nil {
			return facts, ErrState
		}
		facts.InstallationOwned = true
		facts.AccountCompatible = true
		facts.Profile = manifest.Profile
		facts.PendingService = manifest.Version == pendingInstallationVersion
		if h.validateInstallation(ctx, manifest) != nil {
			return facts, ErrState
		}
	} else {
		facts.inspectionStage = "preflight_unit_absence"
		if !status.absent() {
			return facts, ErrState
		}
		facts.inspectionStage = "preflight_manifest_absence"
		if !os.IsNotExist(e) {
			return facts, ErrState
		}

		facts.inspectionStage = "preflight_ownership_state"
		owned, ownErr := h.readOwnership()
		if ownErr == nil {
			if !exists || acct.UID != owned.Installation.UID || acct.GID != owned.Installation.GID || h.validateRetained(owned) != nil {
				return facts, ErrState
			}
			facts.AccountCompatible = true
			facts.Profile = owned.Installation.Profile
			facts.PendingService = owned.Installation.Version == pendingInstallationVersion
			if owned.Status == "prepared" {
				facts.RetainedPreparation = true
			} else if owned.Status == "uninstalled" {
				facts.InstallationOwned = true
				facts.InstallationRemoved = true
			} else {
				return facts, ErrState
			}
			if r.Action == Install && (r.AgentSHA256 != owned.Installation.AgentHash || r.EnrollSHA256 != owned.Installation.EnrollHash || r.SourceSHA256 != owned.Installation.SourceHash || r.BootstrapSHA256 != owned.Installation.BootstrapHash) {
				return facts, ErrState
			}
		} else {
			if !os.IsNotExist(ownErr) || exists {
				return facts, ErrState
			}
			facts.inspectionStage = "preflight_fresh_paths"
			for _, p := range []string{InstallDirectory, publicDirectory, StateDirectory, UnitPath} {
				if _, e := os.Lstat(h.path(p)); !os.IsNotExist(e) {
					return facts, ErrState
				}
			}
			facts.AccountCompatible = true
			if r.Action != Install {
				return facts, ErrState
			}
			facts.inspectionStage = "preflight_bootstrap"
			raw, bootstrap, e := readBootstrap(ctx, r.BootstrapFile, r.BootstrapSHA256)
			clear(raw)
			if e != nil {
				return facts, ErrArtifact
			}
			facts.Profile = bootstrap.Profile
		}
	}
	if e := h.readAdminUpgradeGuard(r); e != nil {
		facts.inspectionStage = "preflight_installation_state"
		return facts, e
	}
	facts.inspectionStage = "preflight_complete_profile"
	if r.Action == Install && r.RequireCompleteProfile {
		raw, bootstrap, err := readBootstrap(ctx, r.BootstrapFile, r.BootstrapSHA256)
		clear(raw)
		if err != nil || bootstrap.CollectionProfile != "managed-operations-v3" || r.ExpectedAgentOrigin != "" && bootstrap.AgentOrigin != r.ExpectedAgentOrigin {
			return facts, ErrContract
		}
		facts.CollectionProfile = bootstrap.CollectionProfile
		facts.AgentOrigin = bootstrap.AgentOrigin
	}
	facts.inspectionStage = "preflight_artifacts"
	if r.Action == Install || r.Action == Upgrade {
		v, e := VerifyInputs(ctx, r)
		if e != nil {
			return facts, e
		}
		v.Close()
	}
	facts.inspectionStage = ""
	return facts, nil
}
func readBootstrap(ctx context.Context, p, digest string) ([]byte, enrollmentclient.Bootstrap, error) {
	if !validDigest(digest) {
		return nil, enrollmentclient.Bootstrap{}, ErrArtifact
	}
	f, info, e := openArtifact(p, 64<<10)
	if e != nil {
		return nil, enrollmentclient.Bootstrap{}, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(raw) > 64<<10 || sum(raw) != digest {
		return nil, enrollmentclient.Bootstrap{}, ErrArtifact
	}
	current, e := f.Stat()
	if e != nil || !sameArtifact(info, current) || ctx.Err() != nil {
		return nil, enrollmentclient.Bootstrap{}, ErrArtifact
	}
	// Parse the exact hashed snapshot; no root adoption of the input file owner.
	b, e := enrollmentclient.ParseBootstrap(raw)
	if e != nil {
		return nil, b, ErrArtifact
	}
	return raw, b, nil
}
func sum(p []byte) string { d := sha256.Sum256(p); return hex.EncodeToString(d[:]) }
func (h *linuxHost) secureDirectory(path string, private bool) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || int(st.Uid) != h.owner || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm() != 0700 {
		return ErrState
	}
	// Protected ancestors are essential: leaf checks alone do not prevent swaps.
	for p := filepath.Dir(path); p != "."; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil {
			return ErrState
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || int(s.Uid) != h.owner && s.Uid != 0 || i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
			return ErrState
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func (h *linuxHost) secureFile(path string, private bool, limit int64) error {
	if e := h.secureDirectory(filepath.Dir(path), false); e != nil {
		return e
	}
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || int(st.Uid) != h.owner || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || private && info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return ErrState
	}
	return nil
}
func (h *linuxHost) readInstallation() (installation, error) {
	var out installation
	p := h.path(ManifestPath)
	if e := h.secureFile(p, false, 8192); e != nil {
		return out, e
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		return out, ErrState
	}
	if lanconfig.StrictObject(raw, &out, "version", "profile", "uid", "gid", "agentHash", "enrollHash", "sourceHash", "bootstrapHash", "unitHash") != nil || !validInstallationVersion(out.Version) || !validAccountID(out.UID) || !validAccountID(out.GID) || (out.Profile != "tls" && out.Profile != "http-test") {
		return out, ErrState
	}
	for _, d := range []string{out.AgentHash, out.EnrollHash, out.SourceHash, out.BootstrapHash, out.UnitHash} {
		if !validDigest(d) {
			return out, ErrState
		}
	}
	return out, nil
}
func (h *linuxHost) validateInstallation(ctx context.Context, m installation) error {
	expected := unitForMode(accountRecord{m.UID, m.GID}, m.Version, m.Profile)
	if expected == "" || sum([]byte(expected)) != m.UnitHash {
		return ErrState
	}
	if h.secureDirectory(h.path(InstallDirectory), false) != nil || h.secureDirectory(h.path(publicDirectory), false) != nil {
		return ErrState
	}
	for _, v := range []struct {
		p, d string
		role BinaryRole
	}{{AgentPath, m.AgentHash, SenderBinary}, {EnrollPath, m.EnrollHash, EnrollmentBinary}} {
		if h.secureFile(h.path(v.p), false, MaxBinaryBytes) != nil {
			return ErrState
		}
		a, e := VerifyBinary(ctx, h.path(v.p), v.d, v.role)
		if e != nil {
			return e
		}
		a.Close()
	}
	for _, v := range []struct {
		p, d string
		max  int64
	}{{UnitPath, m.UnitHash, 64 << 10}, {BootstrapPath, m.BootstrapHash, 64 << 10}} {
		if h.secureFile(h.path(v.p), false, v.max) != nil {
			return ErrState
		}
		raw, e := os.ReadFile(h.path(v.p))
		if e != nil || sum(raw) != v.d {
			return ErrState
		}
	}
	info, e := os.Lstat(h.path(StateDirectory))
	if e != nil {
		return ErrState
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(st.Uid) != m.UID || int(st.Gid) != m.GID || info.Mode().Perm() != 0700 {
		return ErrState
	}
	return nil
}
func actualSystemd() bool {
	if i, e := os.Lstat("/run/systemd/system"); e != nil || !i.IsDir() {
		return false
	}
	if _, e := os.Stat("/sys/fs/cgroup/cgroup.controllers"); e != nil {
		return false
	}
	raw, e := os.ReadFile("/proc/1/comm")
	return e == nil && string(bytes.TrimSpace(raw)) == "systemd"
}
func actualAccount() (accountRecord, bool, error) {
	passwd, e := os.ReadFile("/etc/passwd")
	if e != nil {
		return accountRecord{}, false, ErrPreflight
	}
	groups, e := os.ReadFile("/etc/group")
	if e != nil {
		return accountRecord{}, false, ErrPreflight
	}
	return parseAccountFiles(passwd, groups)
}
func parseAccountFiles(raw, groups []byte) (accountRecord, bool, error) {
	var a accountRecord
	if len(raw) > 1<<20 || len(groups) > 1<<20 {
		return a, false, ErrPreflight
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.Split(line, ":")
		if len(p) < 1 || p[0] != Account {
			continue
		}
		if found || len(p) != 7 || p[5] != StateDirectory || p[6] != nologinPath {
			return a, false, ErrState
		}
		uid, e1 := strconv.Atoi(p[2])
		gid, e2 := strconv.Atoi(p[3])
		if e1 != nil || e2 != nil || !validAccountID(uid) || !validAccountID(gid) || strconv.Itoa(uid) != p[2] || strconv.Itoa(gid) != p[3] {
			return a, false, ErrState
		}
		a = accountRecord{uid, gid}
		found = true
	}
	own := false
	for _, line := range strings.Split(string(groups), "\n") {
		p := strings.Split(line, ":")
		if len(p) != 4 {
			continue
		}
		gid, e := strconv.Atoi(p[2])
		if p[0] == Account {
			if !found || own || e != nil || gid != a.GID || p[3] != "" {
				return a, false, ErrState
			}
			own = true
		} else if found && e == nil && gid == a.GID {
			return a, false, ErrState
		}
		for _, member := range strings.Split(p[3], ",") {
			if member == Account {
				return a, false, ErrState
			}
		}
	}
	if !found {
		return a, false, nil
	}
	if !own {
		return a, false, ErrState
	}
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.Split(line, ":")
		if len(p) != 7 || p[0] == Account {
			continue
		}
		uid, e := strconv.Atoi(p[2])
		if e == nil && uid == a.UID {
			return a, false, ErrState
		}
	}
	return a, true, nil
}

func (b *LinuxBackend) Begin(ctx context.Context, r Request, p Plan) (result Transaction, failure error) {
	checkpoint := Operation("preflight_begin_request")
	defer func() {
		if failure != nil {
			failure = &preflightFailure{checkpoint, failure}
		}
	}()
	if b == nil || b.host == nil || !r.Apply || os.Geteuid() != b.host.owner || ctx.Err() != nil {
		return nil, ErrPreflight
	}
	h := b.host
	dir := h.path(controlDirectory)
	checkpoint = "preflight_begin_control"
	if e := h.ensureControl(dir); e != nil {
		return nil, e
	}
	checkpoint = "preflight_begin_lock"
	var lock int
	var e error
	if r.UpgradeCoordinatorFD != 0 {
		if e = h.readAdminUpgradeGuard(r); e != nil {
			return nil, e
		}
		lock, e = unix.FcntlInt(uintptr(r.UpgradeCoordinatorFD), unix.F_DUPFD_CLOEXEC, 3)
	} else {
		lock, e = unix.Open(filepath.Join(dir, "install.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	}
	if e != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(lock), "installer-lock")
	fail := func() (Transaction, error) { f.Close(); return nil, ErrState }
	if h.secureFile(filepath.Join(dir, "install.lock"), true, 4096) != nil || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail()
	}
	checkpoint = "preflight_begin_journal"
	journalPath := filepath.Join(dir, "transaction.json")
	if _, e := os.Lstat(journalPath); !os.IsNotExist(e) {
		return fail()
	} // Uncertain prior work needs explicit recovery, never automatic cleanup.
	checkpoint = "preflight_begin_entropy"
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return fail()
	}
	version := readyInstallationVersion
	profile := "tls"
	if r.InsecureHTTPTest {
		profile = "http-test"
	}
	if r.PendingService {
		version = pendingInstallationVersion
	}
	checkpoint = "preflight_begin_ownership"
	if r.Action != Install || r.Resume {
		owned, oe := h.readOwnership()
		if oe != nil {
			return fail()
		}
		version = owned.Installation.Version
		profile = owned.Installation.Profile
		if r.Action == Install && (version == pendingInstallationVersion) != r.PendingService {
			return fail()
		}
	}
	t := &linuxTransaction{h: h, lock: f, borrowedLock: r.UpgradeCoordinatorFD != 0, dir: dir, r: r, installationVersion: version, profile: profile, j: installJournal{ID: hex.EncodeToString(nonce[:]), Version: transactionVersion(version), Action: r.Action, Phase: "begun", Changes: []fileChange{}}}
	checkpoint = "preflight_begin_unit"
	status, se := h.unit(ctx)
	if se != nil {
		checkpoint = checkpointFailureStage(se, checkpoint)
		t.Close()
		return nil, ErrPreflight
	}
	t.j.EnabledBefore = status.UnitFileState == "enabled"
	checkpoint = "preflight_begin_artifacts"
	if r.Action == Install || r.Action == Upgrade {
		t.inputs, e = VerifyInputs(ctx, r)
		if e != nil {
			return fail()
		}
	}
	checkpoint = "preflight_begin_bootstrap"
	if r.Action == Install {
		t.bootstrap, _, e = readBootstrap(ctx, r.BootstrapFile, r.BootstrapSHA256)
		if e != nil {
			t.Close()
			return nil, ErrArtifact
		}
	}
	checkpoint = "preflight_begin_save"
	if e = t.save(); e != nil {
		t.Close()
		return nil, ErrState
	}
	return t, nil
}

// JSON contains only fixed paths, hashes, account IDs and transaction metadata.
func encode(v any) []byte { raw, _ := json.Marshal(v); return append(raw, '\n') }
func operationTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 45*time.Second)
}

const controlMarker = "tracebolt.agent-installer-owned.v1\n"

func (h *linuxHost) ensureControl(dir string) error {
	e := os.Mkdir(dir, 0700)
	if e == nil {
		if exclusiveBytes(filepath.Join(dir, "ownership"), []byte(controlMarker), 0600) != nil {
			return ErrState
		}
	} else if !os.IsExist(e) {
		return ErrState
	}
	if h.secureDirectory(dir, true) != nil || h.secureFile(filepath.Join(dir, "ownership"), true, 128) != nil {
		return ErrState
	}
	raw, e := os.ReadFile(filepath.Join(dir, "ownership"))
	if e != nil || string(raw) != controlMarker {
		return ErrState
	}
	return nil
}
