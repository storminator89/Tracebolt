//go:build linux

package cachedupdates

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/fullinventory"
	"localrmm/internal/packagecollector"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// APT policy is read-only. Disable both writable binary caches and fix the
// package/status/source/preferences locations. Native policy (including pins)
// still chooses candidates; we never parse repository URLs or run apt update.
var policyOptions = []string{
	"-o", "RootDir=", "-o", "Dir=/",
	"-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
	"-o", "Dir::State::status=/var/lib/dpkg/status", "-o", "Dir::State::lists=/var/lib/apt/lists",
	"-o", "Dir::Etc::sourcelist=/etc/apt/sources.list", "-o", "Dir::Etc::sourceparts=/etc/apt/sources.list.d",
	"-o", "Dir::Etc::preferences=/etc/apt/preferences", "-o", "Dir::Etc::preferencesparts=/etc/apt/preferences.d",
	"policy",
}

const dpkgFormat = "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Want}\t${db:Status-Status}\t${db:Status-Eflag}\n"

type linuxSource struct {
	paths       map[string]unix.Stat_t
	missing     map[string]bool
	original    fullinventory.SourceInventory
	configBytes int
}

func newNativeSource() (nativeSource, error) {
	return &linuxSource{paths: map[string]unix.Stat_t{}, missing: map[string]bool{}}, nil
}
func (s *linuxSource) close() {}
func (s *linuxSource) inventory(ctx context.Context, generation string, at time.Time) (fullinventory.SourceInventory, error) {
	if e := s.remember("/var/lib/dpkg/status", false); e != nil {
		return fullinventory.SourceInventory{}, e
	}
	inv, e := packagecollector.CollectComplete(ctx, generation, at)
	if e != nil {
		return inv, inventoryFailure(e)
	}
	s.original = inv
	return inv, nil
}
func (s *linuxSource) metadata(ctx context.Context) (time.Time, error) {
	if e := s.remember("/var/lib/apt/lists", false); e != nil {
		if errors.Is(e, sourceFailure(ReasonSourceMissing)) {
			return time.Time{}, sourceFailure(ReasonCacheMissing)
		}
		return time.Time{}, e
	}
	// Pin observed config entries, including absence, so policy changes during a
	// multi-batch attempt cannot silently produce a successful mixed generation.
	for _, p := range []string{"/etc/apt/apt.conf", "/etc/apt/sources.list", "/etc/apt/preferences"} {
		if e := s.remember(p, true); e != nil {
			return time.Time{}, e
		}
		if p == "/etc/apt/apt.conf" && !s.missing[p] {
			if e := s.checkPolicyConfig(p); e != nil {
				return time.Time{}, e
			}
		}
	}
	for _, dir := range []string{"/etc/apt/apt.conf.d", "/etc/apt/sources.list.d", "/etc/apt/preferences.d"} {
		if e := s.rememberDirectory(ctx, dir, true); e != nil {
			return time.Time{}, e
		}
	}
	entries, e := boundedDirectory("/var/lib/apt/lists")
	if e != nil {
		return time.Time{}, e
	}
	oldest := time.Time{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return time.Time{}, ctx.Err()
		}
		name := entry.Name()
		if !packageIndex(name) && !releaseIndex(name) {
			continue
		}
		path := filepath.Join("/var/lib/apt/lists", name)
		if e := s.remember(path, false); e != nil {
			return time.Time{}, e
		}
		st := s.paths[path]
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 {
			return time.Time{}, sourceFailure(ReasonInvalidSource)
		}
		// Release metadata affects APT policy and must be stable too, but it
		// does not change our explicitly Package-index-only age basis.
		if !packageIndex(name) {
			continue
		}
		modified := time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC()
		if oldest.IsZero() || modified.Before(oldest) {
			oldest = modified
		}
	}
	if oldest.IsZero() {
		return time.Time{}, sourceFailure(ReasonCacheMissing)
	}
	return oldest, nil
}
func releaseIndex(name string) bool {
	return strings.HasSuffix(name, "_InRelease") || strings.HasSuffix(name, "_Release") || strings.HasSuffix(name, "_Release.gpg")
}
func packageIndex(name string) bool {
	for _, suffix := range []string{"_Packages", "_Packages.lz4", "_Packages.gz", "_Packages.xz", "_Packages.bz2", "_Packages.zst"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
func boundedDirectory(path string) ([]os.DirEntry, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, osFailure(e)
	}
	f := os.NewFile(uintptr(fd), "cached-update-source-directory")
	defer f.Close()
	entries, e := f.ReadDir(4097)
	if e != nil && e != io.EOF {
		return nil, sourceFailure(ReasonReadFailed)
	}
	if len(entries) > 4096 {
		return nil, sourceFailure(ReasonWorkLimit)
	}
	return entries, nil
}
func (s *linuxSource) rememberDirectory(ctx context.Context, path string, optional bool) error {
	if e := s.remember(path, optional); e != nil {
		return e
	}
	if s.missing[path] {
		return nil
	}
	if s.paths[path].Mode&unix.S_IFMT != unix.S_IFDIR {
		return sourceFailure(ReasonInvalidSource)
	}
	entries, e := boundedDirectory(path)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := s.remember(filepath.Join(path, entry.Name()), false); e != nil {
			return e
		}
		if s.paths[filepath.Join(path, entry.Name())].Mode&unix.S_IFMT != unix.S_IFREG {
			return sourceFailure(ReasonInvalidSource)
		}
		if path == "/etc/apt/apt.conf.d" {
			if e := s.checkPolicyConfig(filepath.Join(path, entry.Name())); e != nil {
				return e
			}
		}
	}
	return nil
}

// Nested APT directives can read untracked external files. This narrow adapter
// fails closed rather than following arbitrary include paths. Directive mentions
// inside comments/strings also conservatively reject that configuration. Dir
// and RootDir settings (flat or nested) can redirect later config loads before
// command-line options are applied; reject them rather than follow untracked paths.
var configDirectivePattern = regexp.MustCompile(`(?i)#\s*(include|clear)\b`)
var configDirectoryPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9_])(rootdir|dir)([^a-z0-9_]|$)`)

func unsupportedConfigDirective(raw []byte) bool {
	// APT concatenates text around block comments (D/**/ir). Reject block
	// markers instead of pretending a raw token regex is a complete APT lexer.
	return bytes.Contains(raw, []byte("/*")) || bytes.Contains(raw, []byte("*/")) || configDirectivePattern.Match(raw) || configDirectoryPattern.Match(raw)
}
func (s *linuxSource) checkPolicyConfig(path string) error {
	const maxConfigBytes = 64 << 10
	before := s.paths[path]
	if before.Size < 0 || before.Size > maxConfigBytes || s.configBytes+int(before.Size) > 2<<20 {
		return sourceFailure(ReasonWorkLimit)
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return osFailure(e)
	}
	f := os.NewFile(uintptr(fd), "cached-update-config")
	defer f.Close()
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || !sameStat(before, opened) {
		return sourceFailure(ReasonSourceChanged)
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if e != nil {
		return sourceFailure(ReasonReadFailed)
	}
	if len(raw) > maxConfigBytes {
		return sourceFailure(ReasonWorkLimit)
	}
	s.configBytes += len(raw)
	if unsupportedConfigDirective(raw) {
		return sourceFailure(ReasonNotSupported)
	}
	return nil
}
func (s *linuxSource) remember(path string, optional bool) error {
	if path != "/" {
		if e := s.remember(filepath.Dir(path), false); e != nil {
			return e
		}
	}
	if _, ok := s.paths[path]; ok {
		return nil
	}
	if s.missing[path] {
		return nil
	}
	var st unix.Stat_t
	e := unix.Lstat(path, &st)
	if optional && errors.Is(e, unix.ENOENT) {
		s.missing[path] = true
		return nil
	}
	if e != nil {
		return osFailure(e)
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || (st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Mode&unix.S_IFMT != unix.S_IFREG) {
		return sourceFailure(ReasonInvalidSource)
	}
	s.paths[path] = st
	return nil
}
func (s *linuxSource) holds(ctx context.Context) (map[string]installedPackage, error) {
	raw, e := runCommand(ctx, "/usr/bin/dpkg-query", []string{"--admindir=/var/lib/dpkg", "--show", "--showformat=" + dpkgFormat})
	if e != nil {
		return nil, e
	}
	return parseInstalled(ctx, raw)
}
func (s *linuxSource) policy(ctx context.Context, packages []installedPackage) (map[string]string, error) {
	if len(packages) == 0 || len(packages) > 128 {
		return nil, sourceFailure(ReasonInvalidSource)
	}
	args := append([]string{}, policyOptions...)
	for _, p := range packages {
		if !packagePattern.MatchString(p.name) || !architecturePattern.MatchString(p.architecture) {
			return nil, sourceFailure(ReasonInvalidSource)
		}
		args = append(args, p.key())
	}
	raw, e := runCommand(ctx, "/usr/bin/apt-cache", args)
	if e != nil {
		return nil, e
	}
	return parsePolicy(ctx, raw, packages)
}
func (s *linuxSource) recheck(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for path, before := range s.paths {
		var after unix.Stat_t
		if unix.Lstat(path, &after) != nil || !sameStat(before, after) {
			return sourceFailure(ReasonSourceChanged)
		}
	}
	for path := range s.missing {
		var st unix.Stat_t
		if e := unix.Lstat(path, &st); !errors.Is(e, unix.ENOENT) {
			return sourceFailure(ReasonSourceChanged)
		}
	}
	final, e := packagecollector.CollectComplete(ctx, s.original.GenerationID, s.original.CollectedAt)
	if e != nil {
		return inventoryFailure(e)
	}
	if !reflect.DeepEqual(final.Release, s.original.Release) || !reflect.DeepEqual(final.Rows, s.original.Rows) {
		return sourceFailure(ReasonSourceChanged)
	}
	return nil
}
func sameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func osFailure(e error) error {
	switch {
	case errors.Is(e, os.ErrNotExist):
		return sourceFailure(ReasonSourceMissing)
	case errors.Is(e, os.ErrPermission):
		return sourceFailure(ReasonPermissionDenied)
	default:
		return sourceFailure(ReasonReadFailed)
	}
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.exceeded = true
		b.cancel()
		return 0, sourceFailure(ReasonWorkLimit)
	}
	return b.Buffer.Write(p)
}
func runCommand(ctx context.Context, path string, args []string) ([]byte, error) {
	// Only two fixed read-only command constructors are reachable. No shell,
	// inherited APT_CONFIG, command substitutions, root elevation, or network API.
	if path != "/usr/bin/apt-cache" && path != "/usr/bin/dpkg-query" {
		return nil, sourceFailure(ReasonInvalidSource)
	}
	for _, directory := range []string{"/", "/usr", "/usr/bin"} {
		var parent unix.Stat_t
		if e := unix.Lstat(directory, &parent); e != nil {
			return nil, osFailure(e)
		}
		if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != 0 || parent.Mode&0022 != 0 {
			return nil, sourceFailure(ReasonInvalidSource)
		}
	}
	var st unix.Stat_t
	if e := unix.Lstat(path, &st); e != nil {
		return nil, osFailure(e)
	}

	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 || st.Mode&0111 == 0 {
		return nil, sourceFailure(ReasonInvalidSource)
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	output := &boundedBuffer{limit: maxCommandBytes, cancel: cancel}
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin", "DPKG_COLORS=never", "DPKG_NLS=0"}
	command.Stdin = nil
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = 100 * time.Millisecond
	e := command.Run()
	if output.exceeded {
		return nil, sourceFailure(ReasonWorkLimit)
	}
	if ctx.Err() != nil {
		return nil, sourceFailure(ReasonTimeout)
	}
	if e != nil {
		return nil, sourceFailure(ReasonReadFailed)
	}
	return output.Bytes(), nil
}
