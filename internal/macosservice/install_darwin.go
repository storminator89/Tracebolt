//go:build darwin

package macosservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/darwinprotect"
	"localrmm/internal/lanconfig"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"
)

const custodyUsedName = "used.json"
const custodyOwnerName = "owner.json"
const custodyUsedBytes = `{"schemaVersion":"tracebolt.macos-service-used.v1","used":true}`

type installSession struct {
	selection Request
	installer *protectedPath
	closed    bool
}

// Open requires the packaged fixed, protected installer and a root invocation.
// The child doing enrollment validation is separately dropped to the exact
// dedicated identity. No read-only call creates a directory or lock file.
func (nativeBackend) Open(ctx context.Context, r Request, _ bool) (InstallSession, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrPreflight
	}
	if _, err := Plan(r); err != nil || r.RenderOnly {
		return nil, ErrRequest
	}
	exe, err := os.Executable()
	if err != nil || exe != InstallerPath {
		return nil, ErrPreflight
	}
	uid, gid, _ := identity(r.ServiceIdentity)
	installer, err := openProtected(InstallerPath, false, uid, gid, true, MaxBinaryBytes)
	if err != nil {
		return nil, ErrPreflight
	}
	fd := installer.nodes[len(installer.nodes)-1].fd
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil || !installer.stable() {
		installer.closeArtifact()
		return nil, ErrPreflight
	}
	return &installSession{selection: r, installer: installer}, nil
}

func (s *installSession) Close() error {
	if s == nil || s.closed {
		return ErrPreflight
	}
	s.closed = true
	fd := s.installer.nodes[len(s.installer.nodes)-1].fd
	stable := s.stableInstallerPath()
	unlock := unix.Flock(fd, unix.LOCK_UN)
	closeErr := s.installer.file.Close()
	s.installer.file = nil
	s.installer.nodes = s.installer.nodes[:len(s.installer.nodes)-1]
	s.installer.close()
	if !stable || unlock != nil || closeErr != nil {
		return ErrPreflight
	}
	return nil
}

func (s *installSession) valid(ctx context.Context) bool {
	return s != nil && !s.closed && ctx != nil && ctx.Err() == nil && s.stableInstallerPath()
}

// The install operation itself creates a child of InstallDirectory, which
// legitimately advances that ancestor's directory timestamps. Keep the held
// path's inode/owner/mode/ACL identity stable while allowing directory link
// counts to advance, and requiring the final
// executable's complete metadata to remain unchanged.
func (s *installSession) stableInstallerPath() bool {
	if s == nil || s.installer == nil || len(s.installer.nodes) == 0 {
		return false
	}
	nodes := s.installer.nodes
	for i, n := range nodes {
		var now, entry unix.Stat_t
		if darwinprotect.Fstat(n.fd, &now) != nil || !sameInstallNode(n.stat, now, i == len(nodes)-1) {
			return false
		}
		if i > 0 {
			// Own custody creation may have changed an ancestor since Open, but
			// the held descriptor and its current pathname entry must agree on
			// every field at this instant, including timestamps/link count.
			if unix.Fstatat(nodes[i-1].fd, n.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameInstallNode(now, entry, true) {
				return false
			}
		}
	}
	return true
}

func sameInstallNode(a, b unix.Stat_t, strict bool) bool {
	return sameHeldInstallIdentity(installNodeIdentity(a), installNodeIdentity(b), strict)
}

func installNodeIdentity(v unix.Stat_t) heldInstallIdentity {
	return heldInstallIdentity{Device: uint64(v.Dev), Inode: v.Ino, UID: v.Uid, GID: v.Gid, Mode: uint32(v.Mode), Links: uint64(v.Nlink), Flags: uint64(v.Flags), Size: v.Size,
		MtimeSeconds: v.Mtim.Sec, MtimeNanoseconds: v.Mtim.Nsec, CtimeSeconds: v.Ctim.Sec, CtimeNanoseconds: v.Ctim.Nsec}
}

func runSelectionChild(ctx context.Context, r Request, registeredHandoff bool) (SelectionEvidence, error) {
	uid, gid, ok := identity(r.ServiceIdentity)
	if !ok || ctx == nil || ctx.Err() != nil {
		return SelectionEvidence{}, ErrPreflight
	}
	run, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	mode := "--internal-selection-check"
	if registeredHandoff {
		mode = "--internal-selection-check-registered"
	}
	cmd := exec.CommandContext(run, InstallerPath, mode, r.Profile, r.ServiceIdentity, r.AgentSHA256, r.SourceArchive, r.SourceSHA256)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
	cmd.WaitDelay = 200 * time.Millisecond
	out := &boundedAccountOutput{limit: 32768}
	errOut := &boundedAccountOutput{limit: 512}
	cmd.Stdout, cmd.Stderr = out, errOut
	if cmd.Run() != nil || run.Err() != nil || out.exceeded || errOut.exceeded {
		return SelectionEvidence{}, ErrPreflight
	}
	var evidence SelectionEvidence
	if json.Unmarshal(out.buffer.Bytes(), &evidence) != nil || !validDigest(evidence.EnrollmentAnchorSHA256) || validateSelectedConfig(evidence.Config, selectedProfile(r)) != nil {
		return SelectionEvidence{}, ErrPreflight
	}
	canonical, _ := json.Marshal(evidence)
	if !bytes.Equal(out.buffer.Bytes(), append(canonical, '\n')) {
		return SelectionEvidence{}, ErrPreflight
	}
	return evidence, nil
}

// RunNativeSelectionChild is an inert private CLI entry point. Even if invoked
// directly it performs only the same nonroot local checks; it has no mutation
// surface and never prints secret material.
func RunNativeSelectionChild(ctx context.Context, args []string, out io.Writer, registeredHandoff bool) int {
	if len(args) != 5 || os.Geteuid() == 0 || os.Getuid() == 0 {
		return 2
	}
	r := Request{Profile: args[0], ServiceIdentity: args[1], AgentSHA256: args[2], SourceArchive: args[3], SourceSHA256: args[4]}
	evidence, err := InspectNativeSelection(ctx, r, registeredHandoff)
	if err != nil || json.NewEncoder(out).Encode(evidence) != nil {
		return 1
	}
	return 0
}

type launchctlOutput struct {
	stdout, stderr string
	exit           int
}

func runLaunchctl(ctx context.Context, args ...string) (launchctlOutput, error) {
	allowed := len(args) == 2 && args[0] == "print" && args[1] == "system/"+Label ||
		len(args) == 2 && args[0] == "print-disabled" && args[1] == "system" ||
		len(args) == 2 && args[0] == "bootout" && args[1] == "system/"+Label ||
		len(args) == 3 && args[0] == "bootstrap" && args[1] == "system" && args[2] == PlistPath
	if !allowed || ctx == nil || ctx.Err() != nil {
		return launchctlOutput{}, ErrPreflight
	}
	limit := 10 * time.Second
	if args[0] == "bootout" {
		limit = 40 * time.Second
	} // plist ExitTimeOut is 30s
	run, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(run, "/bin/launchctl", args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 200 * time.Millisecond
	out := &boundedAccountOutput{limit: 1 << 20}
	errOut := &boundedAccountOutput{limit: 1024}
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	if run.Err() != nil || out.exceeded || errOut.exceeded {
		return launchctlOutput{}, ErrPreflight
	}
	status := launchctlOutput{out.buffer.String(), errOut.buffer.String(), 0}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return launchctlOutput{}, ErrPreflight
		}
		status.exit = exit.ExitCode()
	}
	return status, nil
}

func inspectLaunchctl(ctx context.Context, owner *Ownership) (Presence, string, Presence, error) {
	retained, err := runLaunchctl(ctx, "print-disabled", "system")
	if err != nil || retained.exit != 0 || retained.stderr != "" {
		return "", "", "", ErrPreflight
	}
	override, err := parseDisabledSystem(retained.stdout)
	if err != nil {
		return "", "", "", ErrPreflight
	}
	job, err := runLaunchctl(ctx, "print", "system/"+Label)
	if err != nil {
		return "", "", "", ErrPreflight
	}
	if parseMissingService(job.stdout, job.stderr, job.exit) {
		return Absent, "", override, nil
	}
	if job.exit != 0 || job.stderr != "" || job.stdout == "" {
		return "", "", "", ErrPreflight
	}
	bound := ""
	if owner != nil && parseOwnedJob(job.stdout, *owner) {
		bound = owner.SHA256()
	}
	return Present, bound, override, nil
}

// VerifyNativeLaunchdAbsence is for independently owned package rollback. It
// changes nothing and returns success only for positively observed absence of
// both the fixed system job and every retained override for this exact label.
// It does not inspect the plist, service custody or package-stage marker.
func VerifyNativeLaunchdAbsence(ctx context.Context) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrPreflight
	}
	job, _, override, err := inspectLaunchctl(ctx, nil)
	if err != nil || job != Absent || override != Absent {
		return ErrCollision
	}
	return nil
}

func openCustody(uid, gid int) (*protectedPath, Presence, error) {
	parent, err := openProtected(InstallDirectory, true, uid, gid, false, 0)
	if err != nil {
		return nil, "", ErrPreflight
	}
	defer parent.close()
	var stat unix.Stat_t
	err = unix.Fstatat(parent.nodes[len(parent.nodes)-1].fd, path.Base(CustodyDirectory), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT && parent.stable() {
		return nil, Absent, nil
	}
	if err != nil || !parent.stable() {
		return nil, "", ErrPreflight
	}
	dir, err := openProtected(CustodyDirectory, true, uid, gid, false, 0)
	if err != nil {
		return nil, "", ErrPreflight
	}
	st := dir.nodes[len(dir.nodes)-1].stat
	if st.Uid != 0 || st.Gid != 0 || st.Mode&0777 != 0700 || !parent.stable() {
		dir.close()
		return nil, "", ErrPreflight
	}
	return dir, Present, nil
}

func custodyFile(name string) bool {
	if name == custodyUsedName || name == custodyOwnerName {
		return true
	}
	for _, n := range []string{"phase-1.json", "phase-2.json", "phase-3.json", "phase-4.json"} {
		if name == n {
			return true
		}
	}
	for _, n := range []string{"removal-1.json", "removal-2.json", "removal-3.json", "removal-4.json"} {
		if name == n {
			return true
		}
	}
	return false
}

func inspectCustody(uid, gid int) (Presence, *Ownership, []Receipt, error) {
	dir, presence, err := openCustody(uid, gid)
	if err != nil || presence == Absent {
		return presence, nil, nil, err
	}
	defer dir.close()
	dup, err := unix.Dup(dir.nodes[len(dir.nodes)-1].fd)
	if err != nil {
		return "", nil, nil, ErrPreflight
	}
	file := os.NewFile(uintptr(dup), "macos-service-custody-list")
	names, readErr := file.Readdirnames(-1)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(names) > 10 {
		return "", nil, nil, ErrPreflight
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !custodyFile(name) || seen[name] {
			return "", nil, nil, ErrCollision
		}
		seen[name] = true
	}
	if !seen[custodyUsedName] || !seen[custodyOwnerName] {
		return "", nil, nil, ErrCollision
	}
	used, err := readCustodyFile(custodyUsedName, 256)
	if err != nil || string(used) != custodyUsedBytes {
		return "", nil, nil, ErrCollision
	}
	raw, err := readCustodyFile(custodyOwnerName, 8192)
	if err != nil {
		return "", nil, nil, ErrCollision
	}
	owner, err := DecodeOwnership(raw)
	if err != nil {
		return "", nil, nil, ErrCollision
	}
	var receipts []Receipt
	for i := 1; i <= 4; i++ {
		name := "phase-" + string(rune('0'+i)) + ".json"
		if !seen[name] {
			if i < 4 && seen["phase-"+string(rune('1'+i))+".json"] {
				return "", nil, nil, ErrCollision
			}
			continue
		}
		if len(receipts) != i-1 {
			return "", nil, nil, ErrCollision
		}
		bytes, e := readCustodyFile(name, 1024)
		if e != nil {
			return "", nil, nil, ErrCollision
		}
		receipt, e := DecodeReceipt(bytes, owner)
		if e != nil || receipt.Sequence != i {
			return "", nil, nil, ErrCollision
		}
		receipts = append(receipts, receipt)
	}
	if !dir.stable() {
		return "", nil, nil, ErrPreflight
	}
	return Present, &owner, receipts, nil
}

func readCustodyFile(name string, limit int64) ([]byte, error) {
	if !custodyFile(name) {
		return nil, ErrPreflight
	}
	return readRootFile(CustodyDirectory+"/"+name, limit)
}

func inspectRemovalReceipts(uid, gid int, owner *Ownership) ([]RemovalReceipt, error) {
	if owner == nil {
		return nil, nil
	}
	dir, present, err := openCustody(uid, gid)
	if err != nil || present != Present {
		return nil, ErrPreflight
	}
	defer dir.close()
	var receipts []RemovalReceipt
	for i := 1; i <= 4; i++ {
		name := "removal-" + string(rune('0'+i)) + ".json"
		var st unix.Stat_t
		e := unix.Fstatat(dir.nodes[len(dir.nodes)-1].fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if e == unix.ENOENT {
			continue
		}
		if e != nil || len(receipts) != i-1 {
			return nil, ErrCollision
		}
		raw, e := readCustodyFile(name, 1024)
		if e != nil {
			return nil, ErrCollision
		}
		r, e := DecodeRemovalReceipt(raw, *owner)
		if e != nil || r.Sequence != i {
			return nil, ErrCollision
		}
		receipts = append(receipts, r)
	}
	if !dir.stable() {
		return nil, ErrPreflight
	}
	return receipts, nil
}

func readRootFile(name string, limit int64) ([]byte, error) {
	// ReadProtected validates every held component, private owner-only mode,
	// regular single-link file, ACL and unchanged inode/bytes before returning.
	return lanconfig.ReadProtected(name, true, limit)
}

func writeNoReplace(dir *protectedPath, name string, raw []byte, mode uint32) error {
	if dir == nil || !dir.stable() || len(raw) == 0 || len(raw) > 8192 || strings.Contains(name, "/") || name == "" {
		return ErrPreflight
	}
	fd, err := unix.Openat(dir.nodes[len(dir.nodes)-1].fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return ErrCollision
	}
	file := os.NewFile(uintptr(fd), "macos-service-no-replace")
	n, writeErr := file.Write(raw)
	syncErr := darwinprotect.Sync(fd)
	closeErr := file.Close()
	var refreshed unix.Stat_t
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil || darwinprotect.Sync(dir.nodes[len(dir.nodes)-1].fd) != nil || darwinprotect.Fstat(dir.nodes[len(dir.nodes)-1].fd, &refreshed) != nil {
		return ErrIndeterminate
	}
	dir.nodes[len(dir.nodes)-1].stat = refreshed
	if !dir.stable() {
		return ErrIndeterminate
	}
	return nil
}

func (s *installSession) Inspect(ctx context.Context) (InstallSnapshot, error) {
	if s == nil {
		return InstallSnapshot{}, ErrPreflight
	}
	return inspectStableSelection(ctx, s.selection, s.observe, runSelectionChild)
}

func (s *installSession) observe(ctx context.Context) (InstallSnapshot, error) {
	if !s.valid(ctx) {
		return InstallSnapshot{}, ErrPreflight
	}
	uid, gid, _ := identity(s.selection.ServiceIdentity)
	custody, owner, receipts, err := inspectCustody(uid, gid)
	if err != nil {
		return InstallSnapshot{}, err
	}
	removals, err := inspectRemovalReceipts(uid, gid, owner)
	if err != nil {
		return InstallSnapshot{}, err
	}
	plist, plistHash, err := inspectPlist(uid, gid)
	if err != nil {
		return InstallSnapshot{}, err
	}
	job, jobHash, override, err := inspectLaunchctl(ctx, owner)
	if err != nil || !s.valid(ctx) {
		return InstallSnapshot{}, ErrPreflight
	}
	state := InstallSnapshot{Custody: custody, Owner: owner, Receipts: receipts, RemovalReceipts: removals, Plist: plist, PlistSHA256: plistHash,
		Job: job, JobOwnershipSHA256: jobHash, Override: override}
	return state, nil
}

func inspectPlist(uid, gid int) (Presence, string, error) {
	parent, err := openProtected(path.Dir(PlistPath), true, uid, gid, false, 0)
	if err != nil {
		return "", "", ErrPreflight
	}
	defer parent.close()
	var stat unix.Stat_t
	err = unix.Fstatat(parent.nodes[len(parent.nodes)-1].fd, path.Base(PlistPath), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT && parent.stable() {
		return Absent, "", nil
	}
	if err != nil || !parent.stable() {
		return "", "", ErrPreflight
	}
	plist, err := openProtected(PlistPath, false, uid, gid, false, 16384)
	if err != nil {
		return Present, "", ErrPreflight
	}
	defer plist.closeArtifact()
	if plist.nodes[len(plist.nodes)-1].stat.Mode&0777 != 0644 {
		return Present, "", ErrCollision
	}
	raw, err := io.ReadAll(io.LimitReader(plist.file, 16385))
	if err != nil || len(raw) < 1 || len(raw) > 16384 || !plist.stable() || !parent.stable() {
		return Present, "", ErrPreflight
	}
	return Present, digest(raw), nil
}

func (s *installSession) Claim(ctx context.Context, owner Ownership) error {
	if !s.valid(ctx) || !owner.valid() {
		return ErrPreflight
	}
	uid, gid, _ := identity(s.selection.ServiceIdentity)
	presence, existing, receipts, err := inspectCustody(uid, gid)
	if err != nil || presence != Absent || existing != nil || len(receipts) != 0 {
		return ErrCollision
	}
	parent, err := openProtected(InstallDirectory, true, uid, gid, false, 0)
	if err != nil {
		return ErrPreflight
	}
	defer parent.close()
	if unix.Mkdirat(parent.nodes[len(parent.nodes)-1].fd, path.Base(CustodyDirectory), 0700) != nil {
		return ErrIndeterminate
	}
	if darwinprotect.Sync(parent.nodes[len(parent.nodes)-1].fd) != nil {
		return ErrIndeterminate
	}
	dir, present, err := openCustody(uid, gid)
	if err != nil || present != Present {
		return ErrIndeterminate
	}
	defer dir.close()
	if writeNoReplace(dir, custodyUsedName, []byte(custodyUsedBytes), 0600) != nil {
		return ErrIndeterminate
	}
	raw, _ := json.Marshal(owner)
	if writeNoReplace(dir, custodyOwnerName, raw, 0600) != nil {
		return ErrIndeterminate
	}
	return nil
}

func (s *installSession) AppendReceipt(ctx context.Context, receipt Receipt) error {
	if !s.valid(ctx) {
		return ErrPreflight
	}
	uid, gid, _ := identity(s.selection.ServiceIdentity)
	presence, owner, current, err := inspectCustody(uid, gid)
	if err != nil || presence != Present || owner == nil || len(current) >= 4 || receipt.Sequence != len(current)+1 || receipt != expectedReceipts(*owner)[len(current)] {
		return ErrCollision
	}
	dir, _, err := openCustody(uid, gid)
	if err != nil {
		return ErrPreflight
	}
	defer dir.close()
	raw, _ := json.Marshal(receipt)
	return writeNoReplace(dir, "phase-"+string(rune('0'+receipt.Sequence))+".json", raw, 0600)
}

func (s *installSession) Publish(ctx context.Context, owner Ownership, plist string) error {
	if !s.valid(ctx) || digest([]byte(plist)) != owner.PlistSHA256 {
		return ErrPreflight
	}
	state, err := s.Inspect(ctx)
	if err != nil || state.Owner == nil || *state.Owner != owner || state.Custody != Present || len(state.Receipts) != 1 || state.Receipts[0] != expectedReceipts(owner)[0] || state.Plist != Absent || state.Job != Absent || state.Override != Absent {
		return ErrCollision
	}
	uid, gid, _ := identity(s.selection.ServiceIdentity)
	parent, err := openProtected(path.Dir(PlistPath), true, uid, gid, false, 0)
	if err != nil {
		return ErrPreflight
	}
	defer parent.close()
	if writeNoReplace(parent, path.Base(PlistPath), []byte(plist), 0644) != nil {
		return ErrIndeterminate
	}
	return nil
}

func (s *installSession) Bootstrap(ctx context.Context, owner Ownership) error {
	if !s.valid(ctx) {
		return ErrPreflight
	}
	state, err := s.Inspect(ctx)
	if err != nil || state.Owner == nil || *state.Owner != owner || state.Custody != Present || len(state.Receipts) != 3 || !receiptPrefix(owner, state.Receipts) || state.Plist != Present || state.PlistSHA256 != owner.PlistSHA256 || state.Job != Absent || state.Override != Absent {
		return ErrCollision
	}
	result, err := runLaunchctl(ctx, "bootstrap", "system", PlistPath)
	if err != nil || result.exit != 0 || result.stdout != "" || result.stderr != "" {
		return ErrIndeterminate
	}
	state, err = s.Inspect(ctx)
	if err != nil || state.Job != Present || state.JobOwnershipSHA256 != owner.SHA256() {
		return ErrIndeterminate
	}
	return nil
}

func (s *installSession) AppendRemovalReceipt(ctx context.Context, receipt RemovalReceipt) error {
	if !s.valid(ctx) {
		return ErrPreflight
	}
	state, err := s.Inspect(ctx)
	if err != nil || state.Custody != Present || state.Owner == nil || len(state.Receipts) != 4 || !receiptPrefix(*state.Owner, state.Receipts) || len(state.RemovalReceipts) >= 4 || receipt != expectedRemovalReceipts(*state.Owner)[len(state.RemovalReceipts)] {
		return ErrCollision
	}
	wantPlist, wantJob := Present, Present
	if len(state.RemovalReceipts) >= 1 {
		wantJob = Absent
	}
	if len(state.RemovalReceipts) >= 3 {
		wantPlist = Absent
	}
	if !runtimeMatches(state, *state.Owner, wantPlist, wantJob) {
		return ErrCollision
	}
	uid, gid, _ := identity(s.selection.ServiceIdentity)
	dir, present, err := openCustody(uid, gid)
	if err != nil || present != Present {
		return ErrPreflight
	}
	defer dir.close()
	raw, _ := json.Marshal(receipt)
	return writeNoReplace(dir, "removal-"+string(rune('0'+receipt.Sequence))+".json", raw, 0600)
}

func (s *installSession) Bootout(ctx context.Context, owner Ownership) error {
	if !s.valid(ctx) {
		return ErrPreflight
	}
	state, err := s.Inspect(ctx)
	if err != nil || state.Owner == nil || *state.Owner != owner || len(state.Receipts) != 4 || len(state.RemovalReceipts) != 1 || state.RemovalReceipts[0] != expectedRemovalReceipts(owner)[0] || !runtimeMatches(state, owner, Present, Present) {
		return ErrCollision
	}
	result, err := runLaunchctl(ctx, "bootout", "system/"+Label)
	if err != nil || result.exit != 0 || result.stdout != "" || result.stderr != "" {
		return ErrIndeterminate
	}
	// launchctl may unregister the job before the old foreground process has
	// released its lifetime sender lock. Poll only read-only evidence for at
	// most the documented stop window; never replay bootout on uncertainty.
	deadline := time.Now().Add(35 * time.Second)
	for {
		state, err = s.Inspect(ctx)
		if err == nil && runtimeMatches(state, owner, Present, Absent) {
			return nil
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return ErrIndeterminate
		}
		select {
		case <-ctx.Done():
			return ErrIndeterminate
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *installSession) RemoveOwnedPlist(ctx context.Context, owner Ownership) error {
	if !s.valid(ctx) {
		return ErrPreflight
	}
	state, err := s.Inspect(ctx)
	want := expectedRemovalReceipts(owner)
	if err != nil || state.Owner == nil || *state.Owner != owner || len(state.Receipts) != 4 || len(state.RemovalReceipts) != 3 || state.RemovalReceipts[0] != want[0] || state.RemovalReceipts[1] != want[1] || state.RemovalReceipts[2] != want[2] || !runtimeMatches(state, owner, Present, Absent) {
		return ErrCollision
	}
	uid, gid, _ := identity(s.selection.ServiceIdentity)
	parent, err := openProtected(path.Dir(PlistPath), true, uid, gid, false, 0)
	if err != nil {
		return ErrPreflight
	}
	defer parent.close()
	plist, err := openProtected(PlistPath, false, uid, gid, false, 16384)
	if err != nil {
		return ErrPreflight
	}
	defer plist.closeArtifact()
	raw, err := io.ReadAll(io.LimitReader(plist.file, 16385))
	if err != nil || digest(raw) != owner.PlistSHA256 || !plist.stable() || !parent.stable() {
		return ErrCollision
	}
	var entry unix.Stat_t
	if unix.Fstatat(parent.nodes[len(parent.nodes)-1].fd, path.Base(PlistPath), &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameNode(entry, plist.nodes[len(plist.nodes)-1].stat) {
		return ErrCollision
	}
	if unix.Unlinkat(parent.nodes[len(parent.nodes)-1].fd, path.Base(PlistPath), 0) != nil || darwinprotect.Sync(parent.nodes[len(parent.nodes)-1].fd) != nil {
		return ErrIndeterminate
	}
	return nil
}
