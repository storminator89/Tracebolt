//go:build darwin && !ios

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"localrmm/internal/darwinprotect"
	"localrmm/internal/macosservice"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	accountName   = "_traceboltagent"
	installDir    = "/Library/Application Support/TraceboltAgent"
	sourceDir     = "/Library/Application Support/TraceboltAgentSource"
	sourceFile    = "source.tar"
	ownerFile     = "package-stage.json"
	bootstrapFile = "bootstrap.json"
	plistPath     = "/Library/LaunchDaemons/com.tracebolt.agent.plist"
)

type nativeStage struct{}

func newNativeStage() hostStage { return nativeStage{} }

type limitedOutput struct {
	bytes.Buffer
	max int
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, errRejected
	}
	return b.Buffer.Write(p)
}

func fixedCommand(program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.WaitDelay = 200 * time.Millisecond
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Stdin = nil
	stdout := &limitedOutput{max: 1 << 20}
	stderr := &limitedOutput{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return "", errRejected
	}
	return stdout.String(), nil
}

func records(node, kind, attribute string) (map[string]uint32, error) {
	text, err := fixedCommand("/usr/bin/dscl", node, "-list", kind, attribute)
	if err != nil {
		return nil, err
	}
	out := map[string]uint32{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] == "" {
			return nil, errRejected
		}
		num, e := strconv.ParseUint(fields[1], 10, 32)
		if e != nil || strconv.FormatUint(num, 10) != fields[1] {
			return nil, errRejected
		}
		if _, duplicate := out[fields[0]]; duplicate {
			return nil, errRejected
		}
		out[fields[0]] = uint32(num)
	}
	return out, nil
}

func accountAbsent(uid, gid uint32) error {
	users, e1 := records("/Local/Default", "/Users", "UniqueID")
	groups, e2 := records("/Local/Default", "/Groups", "PrimaryGroupID")
	effectiveUsers, e3 := records("/Search", "/Users", "UniqueID")
	effectiveGroups, e4 := records("/Search", "/Groups", "PrimaryGroupID")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return errRejected
	}
	for _, candidate := range []struct {
		table  map[string]uint32
		number uint32
	}{{users, uid}, {groups, gid}, {effectiveUsers, uid}, {effectiveGroups, gid}} {
		if _, ok := candidate.table[accountName]; ok {
			return errRejected
		}
		for _, value := range candidate.table {
			if value == candidate.number {
				return errRejected
			}
		}
	}
	return nil
}

func exactAttributes(kind string, expected map[string]string) error {
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	// Keep dscl invocation deterministic and without caller-selected attributes.
	if kind == "/Users/"+accountName {
		keys = []string{"UniqueID", "PrimaryGroupID", "UserShell", "NFSHomeDirectory", "IsHidden", "AuthenticationAuthority"}
	} else {
		keys = []string{"PrimaryGroupID"}
	}
	args := append([]string{"/Local/Default", "-read", kind}, keys...)
	text, err := fixedCommand("/usr/bin/dscl", args...)
	if err != nil {
		return err
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return errRejected
		}
		if _, ok := seen[parts[0]]; ok {
			return errRejected
		}
		seen[parts[0]] = parts[1]
	}
	if len(seen) != len(expected) {
		return errRejected
	}
	for key, value := range expected {
		if seen[key] != value {
			return errRejected
		}
	}
	return nil
}

func accountExact(uid, gid uint32) error {
	users, e1 := records("/Local/Default", "/Users", "UniqueID")
	groups, e2 := records("/Local/Default", "/Groups", "PrimaryGroupID")
	effectiveUsers, e3 := records("/Search", "/Users", "UniqueID")
	effectiveGroups, e4 := records("/Search", "/Groups", "PrimaryGroupID")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || users[accountName] != uid || groups[accountName] != gid ||
		effectiveUsers[accountName] != uid || effectiveGroups[accountName] != gid {
		return errRejected
	}
	for _, candidate := range []struct {
		table  map[string]uint32
		number uint32
	}{{users, uid}, {groups, gid}, {effectiveUsers, uid}, {effectiveGroups, gid}} {
		for name, value := range candidate.table {
			if name != accountName && value == candidate.number {
				return errRejected
			}
		}
	}
	if exactAttributes("/Users/"+accountName, map[string]string{
		"UniqueID": strconv.FormatUint(uint64(uid), 10), "PrimaryGroupID": strconv.FormatUint(uint64(gid), 10),
		"UserShell": "/usr/bin/false", "NFSHomeDirectory": "/var/empty", "IsHidden": "1",
		"AuthenticationAuthority": ";DisabledUser;"}) != nil ||
		exactAttributes("/Groups/"+accountName, map[string]string{"PrimaryGroupID": strconv.FormatUint(uint64(gid), 10)}) != nil {
		return errRejected
	}
	groupsText, err := fixedCommand("/usr/bin/id", "-G", accountName)
	if err != nil {
		return errRejected
	}
	seenGroups := map[uint32]bool{}
	for _, word := range strings.Fields(groupsText) {
		num, e := strconv.ParseUint(word, 10, 32)
		if e != nil || strconv.FormatUint(num, 10) != word || seenGroups[uint32(num)] ||
			(uint32(num) != gid && (uint32(num) != 12 || effectiveGroups["everyone"] != 12)) {
			return errRejected
		}
		seenGroups[uint32(num)] = true
	}
	if !seenGroups[gid] {
		return errRejected
	}
	return nil
}

func createAccount(uid, gid uint32) error {
	if accountAbsent(uid, gid) != nil {
		return errRejected
	}
	group := "/Groups/" + accountName
	user := "/Users/" + accountName
	if _, err := fixedCommand("/usr/bin/dscl", "/Local/Default", "-create", group); err != nil {
		return errRejected
	}
	groupFields := map[string]string{}
	if setExactAttribute(group, groupFields, "PrimaryGroupID", strconv.FormatUint(uint64(gid), 10)) != nil {
		return errRejected
	}
	// Before creating the user, recheck the selected numeric IDs through both
	// local records and the effective search policy. A dscl -create sequence is
	// not atomic no-replace, so any intervening ambiguity stops without repair.
	for _, node := range []string{"/Local/Default", "/Search"} {
		users, e1 := records(node, "/Users", "UniqueID")
		groups, e2 := records(node, "/Groups", "PrimaryGroupID")
		if e1 != nil || e2 != nil || groups[accountName] != gid {
			return errRejected
		}
		if _, ok := users[accountName]; ok {
			return errRejected
		}
		for name, value := range users {
			if value == uid || name == accountName {
				return errRejected
			}
		}
		for name, value := range groups {
			if name != accountName && value == gid {
				return errRejected
			}
		}
	}
	if _, err := fixedCommand("/usr/bin/dscl", "/Local/Default", "-create", user); err != nil {
		return errRejected
	}
	userFields := map[string]string{}
	if setExactAttribute(user, userFields, "UniqueID", strconv.FormatUint(uint64(uid), 10)) != nil {
		return errRejected
	}
	for _, node := range []string{"/Local/Default", "/Search"} {
		users, err := records(node, "/Users", "UniqueID")
		if err != nil || users[accountName] != uid {
			return errRejected
		}
		for name, value := range users {
			if name != accountName && value == uid {
				return errRejected
			}
		}
	}
	for _, field := range []struct{ key, value string }{
		{"PrimaryGroupID", strconv.FormatUint(uint64(gid), 10)},
		{"RealName", "Tracebolt Agent"},
		{"UserShell", "/usr/bin/false"},
		{"NFSHomeDirectory", "/var/empty"},
		{"IsHidden", "1"},
		{"AuthenticationAuthority", ";DisabledUser;"},
	} {
		if setExactAttribute(user, userFields, field.key, field.value) != nil {
			return errRejected
		}
	}
	return accountExact(uid, gid)
}

func partialAttributes(record string, expected map[string]string, next string) error {
	text, err := fixedCommand("/usr/bin/dscl", "/Local/Default", "-read", record)
	if err != nil {
		return errRejected
	}
	return exactPartialRecord(text, accountName, expected, next)
}

func setExactAttribute(record string, expected map[string]string, key, value string) error {
	if partialAttributes(record, expected, key) != nil {
		return errRejected
	}
	if _, err := fixedCommand("/usr/bin/dscl", "/Local/Default", "-create", record, key, value); err != nil {
		return errRejected
	}
	expected[key] = value
	return partialAttributes(record, expected, "")
}

type heldDir struct {
	fd   int
	stat unix.Stat_t
}

func (d *heldDir) close() {
	if d != nil && d.fd >= 0 {
		_ = unix.Close(d.fd)
		d.fd = -1
	}
}

func rootDir(name string) (*heldDir, error) {
	if !path.IsAbs(name) || path.Clean(name) != name {
		return nil, errRejected
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRejected
	}
	current := "/"
	check := func(fd int) (unix.Stat_t, error) {
		var st unix.Stat_t
		if darwinprotect.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return st, errRejected
		}
		return st, nil
	}
	if _, err = check(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" {
			continue
		}
		child, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = unix.Close(fd)
			return nil, errRejected
		}
		var st unix.Stat_t
		st, err = check(child)
		if err != nil {
			_ = unix.Close(child)
			_ = unix.Close(fd)
			return nil, err
		}
		var entry unix.Stat_t
		if unix.Fstatat(fd, part, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Dev != entry.Dev || st.Ino != entry.Ino {
			_ = unix.Close(child)
			_ = unix.Close(fd)
			return nil, errRejected
		}
		_ = unix.Close(fd)
		fd = child
		current = path.Join(current, part)
	}
	_ = current
	var st unix.Stat_t
	if st, err = check(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &heldDir{fd: fd, stat: st}, nil
}

func absent(parent *heldDir, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(parent.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT
}

func makeDir(parent *heldDir, name string, mode uint32, uid, gid uint32) (*heldDir, error) {
	if !absent(parent, name) || unix.Mkdirat(parent.fd, name, mode) != nil {
		return nil, errRejected
	}
	fd, err := unix.Openat(parent.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRejected
	}
	d := &heldDir{fd: fd}
	if unix.Fchown(fd, int(uid), int(gid)) != nil || unix.Fchmod(fd, mode) != nil || darwinprotect.Fstat(fd, &d.stat) != nil ||
		d.stat.Mode&unix.S_IFMT != unix.S_IFDIR || d.stat.Uid != uid || d.stat.Gid != gid || d.stat.Mode&0777 != uint16(mode) ||
		darwinprotect.Sync(fd) != nil || darwinprotect.Sync(parent.fd) != nil {
		d.close()
		return nil, errRejected
	}
	return d, nil
}

func writeAsset(parent *heldDir, name string, content []byte, mode uint32) error {
	fd, err := unix.Openat(parent.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errRejected
	}
	f := os.NewFile(uintptr(fd), "package-asset")
	if _, err = f.Write(content); err == nil {
		err = unix.Fchmod(fd, mode)
	}
	if err == nil {
		err = darwinprotect.Sync(fd)
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || darwinprotect.Sync(parent.fd) != nil {
		return errRejected
	}
	return nil
}

func exactFile(parent *heldDir, name string, content []byte, mode uint32) error {
	fd, err := unix.Openat(parent.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return errRejected
	}
	f := os.NewFile(uintptr(fd), "package-owned-file")
	defer f.Close()
	var st unix.Stat_t
	if darwinprotect.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 ||
		st.Mode&0777 != uint16(mode) || st.Size != int64(len(content)) {
		return errRejected
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, int64(len(content))+1)); err != nil {
		return errRejected
	}
	want := sha256.Sum256(content)
	if !bytes.Equal(h.Sum(nil), want[:]) {
		return errRejected
	}
	var after unix.Stat_t
	if darwinprotect.Fstat(fd, &after) != nil || st.Dev != after.Dev || st.Ino != after.Ino || st.Size != after.Size || st.Mtim != after.Mtim || st.Ctim != after.Ctim {
		return errRejected
	}
	return nil
}

func dirEntries(d *heldDir) ([]string, error) {
	duplicate, err := unix.Dup(d.fd)
	if err != nil {
		return nil, errRejected
	}
	f := os.NewFile(uintptr(duplicate), "package-dir-list")
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, errRejected
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

func sameNames(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	actual := map[string]bool{}
	for _, name := range got {
		if actual[name] {
			return false
		}
		actual[name] = true
	}
	for _, name := range want {
		if !actual[name] {
			return false
		}
	}
	return true
}

func ownerBytes(uid, gid uint32, p packageBytes) []byte {
	m := map[string]any{"schema": "tracebolt.macos-package-stage-owner.v1",
		"serviceIdentity": fmt.Sprintf("%d:%d", uid, gid), "packageSHA256": p.Digest,
		"sourceSHA256": p.Manifest.Assets["source/source.tar"].SHA256,
		"sourceCommit": p.Manifest.SourceCommit, "target": p.Manifest.Target,
		"profile": p.Profile, "bootstrapSHA256": p.BootstrapSHA}
	raw, _ := canonicalJSON(m)
	return raw
}

func (nativeStage) Inspect(uid, gid uint32, p packageBytes, rollback bool) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || (p.Profile != "basic-readonly-v1" && p.Profile != "macos-read-inventory-v1") ||
		!validSHA(p.BootstrapSHA) || len(p.Bootstrap) == 0 || len(p.Bootstrap) > 64<<10 {
		return errRejected
	}
	h := sha256.Sum256(p.Bootstrap)
	if hex.EncodeToString(h[:]) != p.BootstrapSHA {
		return errRejected
	}
	base, err := rootDir("/Library/Application Support")
	if err != nil {
		return errRejected
	}
	defer base.close()
	launch, err := rootDir("/Library/LaunchDaemons")
	if err != nil {
		return errRejected
	}
	defer launch.close()
	if !absent(launch, path.Base(plistPath)) {
		return errRejected
	}
	// Plist absence alone cannot rule out a loaded or disabled retained job.
	// Reuse the service installer's strict fixed-label/domain inspection.
	if macosservice.VerifyNativeLaunchdAbsence(context.Background()) != nil {
		return errRejected
	}
	if !rollback {
		if accountAbsent(uid, gid) != nil || !absent(base, path.Base(installDir)) || !absent(base, path.Base(sourceDir)) {
			return errRejected
		}
		return nil
	}
	if accountExact(uid, gid) != nil {
		return errRejected
	}
	install, err := rootDir(installDir)
	if err != nil {
		return errRejected
	}
	defer install.close()
	source, err := rootDir(sourceDir)
	if err != nil {
		return errRejected
	}
	defer source.close()
	stateFD, err := unix.Openat(install.fd, "state", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errRejected
	}
	state := &heldDir{fd: stateFD}
	defer state.close()
	if darwinprotect.Fstat(state.fd, &state.stat) != nil || state.stat.Uid != uid || state.stat.Gid != gid || state.stat.Mode&0777 != 0700 ||
		!absent(state, "enrollment") || !absent(install, "service-registration") {
		return errRejected
	}
	stateNames, e1 := dirEntries(state)
	installNames, e2 := dirEntries(install)
	sourceNames, e3 := dirEntries(source)
	if e1 != nil || e2 != nil || e3 != nil || !sameNames(stateNames) ||
		!sameNames(installNames, "state", "enroll-agent", "macos-agent", "macos-agent-service", "macos-package-prepare", ownerFile, bootstrapFile) ||
		!sameNames(sourceNames, sourceFile) {
		return errRejected
	}
	if exactFile(install, ownerFile, ownerBytes(uid, gid, p), 0600) != nil {
		return errRejected
	}
	if exactFile(install, bootstrapFile, p.Bootstrap, 0644) != nil {
		return errRejected
	}
	for _, name := range []string{"enroll-agent", "macos-agent", "macos-agent-service", "macos-package-prepare"} {
		if exactFile(install, name, p.Files["bin/"+name], 0755) != nil {
			return errRejected
		}
	}
	return exactFile(source, sourceFile, p.Files["source/source.tar"], 0644)
}

func (n nativeStage) Apply(uid, gid uint32, p packageBytes) error {
	if n.Inspect(uid, gid, p, false) != nil {
		return errRejected
	}
	if createAccount(uid, gid) != nil {
		return errRejected
	}
	base, err := rootDir("/Library/Application Support")
	if err != nil {
		return errRejected
	}
	defer base.close()
	install, err := makeDir(base, path.Base(installDir), 0755, 0, 0)
	if err != nil {
		return errRejected
	}
	defer install.close()
	source, err := makeDir(base, path.Base(sourceDir), 0755, 0, 0)
	if err != nil {
		return errRejected
	}
	defer source.close()
	if writeAsset(install, ownerFile, ownerBytes(uid, gid, p), 0600) != nil {
		return errRejected
	}
	if writeAsset(install, bootstrapFile, p.Bootstrap, 0644) != nil {
		return errRejected
	}
	state, err := makeDir(install, "state", 0700, uid, gid)
	if err != nil {
		return errRejected
	}
	state.close()
	for _, name := range []string{"enroll-agent", "macos-agent", "macos-agent-service", "macos-package-prepare"} {
		if writeAsset(install, name, p.Files["bin/"+name], 0755) != nil {
			return errRejected
		}
	}
	if writeAsset(source, sourceFile, p.Files["source/source.tar"], 0644) != nil {
		return errRejected
	}
	if accountExact(uid, gid) != nil {
		return errRejected
	}
	return n.Inspect(uid, gid, p, true)
}

func (n nativeStage) Rollback(uid, gid uint32, p packageBytes) error {
	if n.Inspect(uid, gid, p, true) != nil {
		return errRejected
	}
	base, err := rootDir("/Library/Application Support")
	if err != nil {
		return errRejected
	}
	defer base.close()
	install, err := rootDir(installDir)
	if err != nil {
		return errRejected
	}
	defer install.close()
	source, err := rootDir(sourceDir)
	if err != nil {
		return errRejected
	}
	defer source.close()
	for _, name := range []string{"macos-package-prepare", "macos-agent-service", "macos-agent", "enroll-agent", bootstrapFile, ownerFile} {
		if unix.Unlinkat(install.fd, name, 0) != nil || darwinprotect.Sync(install.fd) != nil {
			return errRejected
		}
	}
	if unix.Unlinkat(source.fd, sourceFile, 0) != nil || darwinprotect.Sync(source.fd) != nil {
		return errRejected
	}
	if unix.Unlinkat(install.fd, "state", unix.AT_REMOVEDIR) != nil || darwinprotect.Sync(install.fd) != nil {
		return errRejected
	}
	if unix.Unlinkat(base.fd, path.Base(sourceDir), unix.AT_REMOVEDIR) != nil || darwinprotect.Sync(base.fd) != nil {
		return errRejected
	}
	if unix.Unlinkat(base.fd, path.Base(installDir), unix.AT_REMOVEDIR) != nil || darwinprotect.Sync(base.fd) != nil {
		return errRejected
	}
	// Deliberately retain the dedicated account. Its removal is a separate
	// security-sensitive operation, never implied by undoing staged files.
	return nil
}
