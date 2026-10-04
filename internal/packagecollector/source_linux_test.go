//go:build linux

package packagecollector

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/linuxpackages"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

type descriptorFixture struct {
	t    *testing.T
	root string
	uid  uint32
}

func newDescriptorFixture(t *testing.T) *descriptorFixture {
	t.Helper()
	// All descriptor operations, permissions and mutations are constrained to
	// this disposable, explicit test root, never the machine's release/status.
	f := &descriptorFixture{t: t, root: filepath.Join(t.TempDir(), "root"), uid: uint32(os.Getuid())}
	for _, name := range []string{"etc", "usr/lib", "var/lib/dpkg"} {
		f.mkdir(name)
	}
	f.write("etc/os-release", releaseText)
	f.write("usr/lib/os-release", "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
	f.write("var/lib/dpkg/status", statusText)
	return f
}
func (f *descriptorFixture) path(name string) string { return filepath.Join(f.root, name) }
func (f *descriptorFixture) mkdir(name string) {
	f.t.Helper()
	if err := os.MkdirAll(f.path(name), 0700); err != nil {
		f.t.Fatal(err)
	}
}
func (f *descriptorFixture) write(name, data string) {
	f.t.Helper()
	if err := os.WriteFile(f.path(name), []byte(data), 0600); err != nil {
		f.t.Fatal(err)
	}
}
func (f *descriptorFixture) remove(name string) {
	f.t.Helper()
	if err := os.Remove(f.path(name)); err != nil {
		f.t.Fatal(err)
	}
}
func (f *descriptorFixture) rename(old, new string) {
	f.t.Helper()
	if err := os.Rename(f.path(old), f.path(new)); err != nil {
		f.t.Fatal(err)
	}
}
func (f *descriptorFixture) symlink(name, target string) {
	f.t.Helper()
	if err := os.Symlink(target, f.path(name)); err != nil {
		f.t.Fatal(err)
	}
}
func (f *descriptorFixture) mode(name string, mode os.FileMode) {
	f.t.Helper()
	if err := os.Chmod(f.path(name), mode); err != nil {
		f.t.Fatal(err)
	}
}
func (f *descriptorFixture) factory() (sourceProvider, error) {
	return newLinuxProvider(func() (int, error) { return unix.Open(f.root, directoryFlags, 0) }, f.uid)
}
func (f *descriptorFixture) collect() linuxpackages.Snapshot {
	f.t.Helper()
	s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, f.factory)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := linuxpackages.Validate(s); err != nil {
		f.t.Fatal(err)
	}
	return s
}
func TestDescriptorReleasePrecedenceAndExactLinks(t *testing.T) {
	for _, tc := range []struct {
		name, link string
		remove     bool
		target     linuxpackages.ReleaseTarget
	}{
		{name: "regular-precedence", target: linuxpackages.Debian13},
		{name: "absent-fallback", remove: true, target: linuxpackages.Ubuntu2404},
		{name: "relative-allowlist", remove: true, link: "../usr/lib/os-release", target: linuxpackages.Ubuntu2404},
		{name: "absolute-allowlist", remove: true, link: "/usr/lib/os-release", target: linuxpackages.Ubuntu2404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDescriptorFixture(t)
			if tc.remove {
				f.remove("etc/os-release")
			}
			if tc.link != "" {
				f.symlink("etc/os-release", tc.link)
			}
			s := f.collect()
			if s.Release.Quality != linuxpackages.Healthy || s.Release.Fields.Target() != tc.target || s.Inventory.Quality != linuxpackages.Healthy {
				t.Fatalf("%+v", s)
			}
		})
	}
}
func TestDescriptorRejectsUnsafeOrNonregularSourcesWithoutFallback(t *testing.T) {
	cases := []struct {
		name   string
		kind   sourceKind
		setup  func(*descriptorFixture)
		reason linuxpackages.Reason
	}{
		{"release-malformed", releaseSource, func(f *descriptorFixture) { f.write("etc/os-release", "ID=\"unterminated") }, linuxpackages.ReasonInvalidSource},
		{"release-unsafe-mode", releaseSource, func(f *descriptorFixture) { f.mode("etc/os-release", 0666) }, linuxpackages.ReasonInvalidSource},
		{"release-parent-unsafe", releaseSource, func(f *descriptorFixture) { f.mode("etc", 0777) }, linuxpackages.ReasonInvalidSource},
		{"release-parent-symlink", releaseSource, func(f *descriptorFixture) { f.rename("etc", "saved-etc"); f.symlink("etc", "saved-etc") }, linuxpackages.ReasonInvalidSource},
		{"release-parent-absent", releaseSource, func(f *descriptorFixture) { f.rename("etc", "saved-etc") }, linuxpackages.ReasonSourceMissing},
		{"release-parent-file", releaseSource, func(f *descriptorFixture) { f.rename("etc", "saved-etc"); f.write("etc", "not a directory") }, linuxpackages.ReasonInvalidSource},
		{"release-other-link", releaseSource, func(f *descriptorFixture) {
			f.remove("etc/os-release")
			f.symlink("etc/os-release", "../usr/lib/./os-release")
		}, linuxpackages.ReasonInvalidSource},
		{"release-link-chain", releaseSource, func(f *descriptorFixture) {
			f.remove("etc/os-release")
			f.symlink("etc/os-release", "../usr/lib/os-release")
			f.rename("usr/lib/os-release", "usr/lib/other")
			f.symlink("usr/lib/os-release", "other")
		}, linuxpackages.ReasonInvalidSource},
		{"release-directory", releaseSource, func(f *descriptorFixture) { f.remove("etc/os-release"); f.mkdir("etc/os-release") }, linuxpackages.ReasonInvalidSource},
		{"release-fifo", releaseSource, func(f *descriptorFixture) {
			f.remove("etc/os-release")
			if err := unix.Mkfifo(f.path("etc/os-release"), 0600); err != nil {
				f.t.Fatal(err)
			}
		}, linuxpackages.ReasonInvalidSource},
		{"target-parent-unsafe", releaseSource, func(f *descriptorFixture) { f.remove("etc/os-release"); f.mode("usr/lib", 0777) }, linuxpackages.ReasonInvalidSource},
		{"target-leaf-unsafe", releaseSource, func(f *descriptorFixture) { f.remove("etc/os-release"); f.mode("usr/lib/os-release", 0666) }, linuxpackages.ReasonInvalidSource},
		{"target-missing", releaseSource, func(f *descriptorFixture) { f.remove("etc/os-release"); f.remove("usr/lib/os-release") }, linuxpackages.ReasonSourceMissing},
		{"inventory-parent-unsafe", inventorySource, func(f *descriptorFixture) { f.mode("var/lib/dpkg", 0777) }, linuxpackages.ReasonInvalidSource},
		{"inventory-parent-symlink", inventorySource, func(f *descriptorFixture) {
			f.rename("var/lib/dpkg", "var/lib/saved")
			f.symlink("var/lib/dpkg", "saved")
		}, linuxpackages.ReasonInvalidSource},
		{"inventory-leaf-unsafe", inventorySource, func(f *descriptorFixture) { f.mode("var/lib/dpkg/status", 0666) }, linuxpackages.ReasonInvalidSource},
		{"inventory-leaf-symlink", inventorySource, func(f *descriptorFixture) {
			f.rename("var/lib/dpkg/status", "var/lib/dpkg/saved")
			f.symlink("var/lib/dpkg/status", "saved")
		}, linuxpackages.ReasonInvalidSource},
		{"inventory-fifo", inventorySource, func(f *descriptorFixture) {
			f.remove("var/lib/dpkg/status")
			if err := unix.Mkfifo(f.path("var/lib/dpkg/status"), 0600); err != nil {
				f.t.Fatal(err)
			}
		}, linuxpackages.ReasonInvalidSource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDescriptorFixture(t)
			tc.setup(f)
			s := f.collect()
			assertUnavailable(t, s, tc.kind == releaseSource, tc.reason)
			if tc.kind == releaseSource && s.Inventory.Quality != linuxpackages.Healthy || tc.kind == inventorySource && s.Release.Quality != linuxpackages.Healthy {
				t.Fatal("unaffected source was cleared")
			}
		})
	}
}
func TestDescriptorRootTrustAndOwnership(t *testing.T) {
	for _, wrongOwner := range []bool{false, true} {
		t.Run(map[bool]string{true: "wrong-owner", false: "writable-root"}[wrongOwner], func(t *testing.T) {
			f := newDescriptorFixture(t)
			if wrongOwner {
				f.uid++
			} else {
				f.mode("", 0777)
			}
			s := f.collect()
			assertUnavailable(t, s, true, linuxpackages.ReasonInvalidSource)
			assertUnavailable(t, s, false, linuxpackages.ReasonInvalidSource)
		})
	}
}
func TestDescriptorOversizeRejectsBeforeReading(t *testing.T) {
	for _, tc := range []struct {
		path string
		cap  int64
		kind sourceKind
	}{{"etc/os-release", linuxpackages.MaxOSReleaseBytes, releaseSource}, {"var/lib/dpkg/status", linuxpackages.MaxDpkgBytes, inventorySource}} {
		t.Run(tc.path, func(t *testing.T) {
			f := newDescriptorFixture(t)
			if err := os.Truncate(f.path(tc.path), tc.cap+1); err != nil {
				t.Fatal(err)
			}
			s := f.collect()
			assertUnavailable(t, s, tc.kind == releaseSource, linuxpackages.ReasonInvalidSource)
		})
	}
}
func TestDescriptorFlagsAndCleanup(t *testing.T) {
	f := newDescriptorFixture(t)
	p, err := f.factory()
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	opened, err := p.open(releaseSource)
	if err != nil {
		t.Fatal(err)
	}
	s := opened.(*linuxSource)
	flags, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 || flags&unix.O_NOFOLLOW == 0 {
		t.Fatal("missing read flags")
	}
	closeFlags, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFD, 0)
	if err != nil || closeFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("missing CLOEXEC")
	}
	for _, n := range s.nodes {
		flags, err := unix.FcntlInt(uintptr(n.fd), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NOFOLLOW == 0 || flags&unix.O_PATH == 0 {
			t.Fatal("unsafe pinned node flags")
		}
	}
	s.close()
	if s.fd != -1 || len(s.nodes) != 0 {
		t.Fatal("resources retained")
	}
}
func TestDescriptorFileAndPathMutationAfterEOF(t *testing.T) {
	for _, mutate := range []string{"replace", "in-place", "mode", "parent-replace", "root-replace"} {
		t.Run(mutate, func(t *testing.T) {
			f := newDescriptorFixture(t)
			p, err := f.factory()
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			s, err := p.open(releaseSource)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if _, err := io.ReadAll(s); err != nil {
				t.Fatal(err)
			}
			switch mutate {
			case "replace":
				f.write("etc/replacement", releaseText)
				f.rename("etc/replacement", "etc/os-release")
			case "in-place":
				f.write("etc/os-release", strings.Replace(releaseText, "debian", "ubuntu", 1))
			case "mode":
				f.mode("etc/os-release", 0400)
			case "parent-replace":
				f.rename("etc", "old-etc")
				f.mkdir("etc")
				f.write("etc/os-release", releaseText)
			case "root-replace":
				old := f.root
				if err := os.Rename(old, old+"-old"); err != nil {
					t.Fatal(err)
				}
				f.mkdir("etc")
				f.write("etc/os-release", releaseText)
			}
			if got := failureReason(s.recheck()); got != linuxpackages.ReasonSourceChanged {
				t.Fatalf("mutation not detected: %s", got)
			}
		})
	}
}

type hookProvider struct {
	sourceProvider
	onOpen func(sourceKind)
}

func (p *hookProvider) open(kind sourceKind) (source, error) {
	if p.onOpen != nil {
		p.onOpen(kind)
	}
	return p.sourceProvider.open(kind)
}
func TestDescriptorFinalCrossSourceRecheck(t *testing.T) {
	for _, change := range []string{"release-replaced", "symlink-replaced", "target-replaced", "fallback-shadowed", "parent-mode", "inventory-failed"} {
		t.Run(change, func(t *testing.T) {
			f := newDescriptorFixture(t)
			if change == "symlink-replaced" || change == "target-replaced" {
				f.remove("etc/os-release")
				f.symlink("etc/os-release", "../usr/lib/os-release")
			}
			if change == "fallback-shadowed" {
				f.remove("etc/os-release")
			}
			factory := func() (sourceProvider, error) {
				p, err := f.factory()
				if err != nil {
					return nil, err
				}
				return &hookProvider{sourceProvider: p, onOpen: func(kind sourceKind) {
					if kind != inventorySource {
						return
					}
					switch change {
					case "release-replaced", "inventory-failed":
						f.write("etc/replacement", releaseText)
						f.rename("etc/replacement", "etc/os-release")
						if change == "inventory-failed" {
							f.write("var/lib/dpkg/status", "broken")
						}
					case "symlink-replaced":
						f.remove("etc/os-release")
						f.symlink("etc/os-release", "/usr/lib/os-release")
					case "target-replaced":
						f.write("usr/lib/replacement", releaseText)
						f.rename("usr/lib/replacement", "usr/lib/os-release")
					case "fallback-shadowed":
						f.write("etc/os-release", releaseText)
					case "parent-mode":
						f.mode("etc", 0777)
					}
				}}, nil
			}
			s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, factory)
			if err != nil {
				t.Fatal(err)
			}
			assertUnavailable(t, s, true, linuxpackages.ReasonSourceChanged)
			if change != "inventory-failed" && s.Inventory.Quality != linuxpackages.Healthy {
				t.Fatal("inventory cleared")
			}
		})
	}
}
func TestFixedOSFailureMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason linuxpackages.Reason
	}{{unix.EACCES, linuxpackages.ReasonPermissionDenied}, {unix.EPERM, linuxpackages.ReasonPermissionDenied}, {unix.ENOENT, linuxpackages.ReasonSourceMissing}, {unix.ELOOP, linuxpackages.ReasonInvalidSource}, {unix.ENOTDIR, linuxpackages.ReasonInvalidSource}, {errors.New("private detail"), linuxpackages.ReasonReadFailed}} {
		if got := failureReason(osFailure(tc.err)); got != tc.reason {
			t.Fatalf("got %s want %s", got, tc.reason)
		}
	}
}
func TestLeafWrongOwnerRejectsBeforeRead(t *testing.T) {
	f := newDescriptorFixture(t)
	p, err := f.factory()
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	lp := p.(*linuxProvider)
	s := &linuxSource{provider: lp, fd: -1, missingParent: -1}
	defer s.close()
	parent, err := s.walk("etc")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := s.probe(parent, "os-release")
	if err != nil {
		t.Fatal(err)
	}
	// Inject ownership metadata rather than changing actual fixture ownership.
	leaf.before.Uid++
	if got := failureReason(s.readRegular(leaf, linuxpackages.MaxOSReleaseBytes)); got != linuxpackages.ReasonInvalidSource || s.fd != -1 {
		t.Fatal("wrong owner read")
	}
}

func TestDeniedOrFailedEtcNeverFallsBack(t *testing.T) {
	for _, injected := range []error{unix.EACCES, unix.EPERM, unix.EIO} {
		t.Run(injected.Error(), func(t *testing.T) {
			f := newDescriptorFixture(t)
			factory := func() (sourceProvider, error) {
				p, err := f.factory()
				if err != nil {
					return nil, err
				}
				lp := p.(*linuxProvider)
				base := lp.openAt
				lp.openAt = func(parent int, name string, flags int) (int, error) {
					if name == "os-release" {
						return -1, injected
					}
					if name == "usr" {
						t.Error("fell back after non-ENOENT error")
					}
					return base(parent, name, flags)
				}
				return p, nil
			}
			s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, factory)
			if err != nil {
				t.Fatal(err)
			}
			assertUnavailable(t, s, true, failureReason(osFailure(injected)))
			if s.Inventory.Quality != linuxpackages.Healthy {
				t.Fatal("inventory not independent")
			}
		})
	}
}
func TestPathSwapBetweenProbeAndReadOpen(t *testing.T) {
	for _, replacement := range []string{"file", "symlink", "fifo", "missing"} {
		t.Run(replacement, func(t *testing.T) {
			f := newDescriptorFixture(t)
			factory := func() (sourceProvider, error) {
				p, err := f.factory()
				if err != nil {
					return nil, err
				}
				lp := p.(*linuxProvider)
				base := lp.openAt
				lp.openAt = func(parent int, name string, flags int) (int, error) {
					if name == "os-release" && flags == readFlags {
						f.remove("etc/os-release")
						switch replacement {
						case "file":
							f.write("etc/os-release", releaseText)
						case "symlink":
							f.symlink("etc/os-release", "../usr/lib/os-release")
						case "fifo":
							if err := unix.Mkfifo(f.path("etc/os-release"), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
					return base(parent, name, flags)
				}
				return p, nil
			}
			s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, factory)
			if err != nil {
				t.Fatal(err)
			}
			assertUnavailable(t, s, true, linuxpackages.ReasonSourceChanged)
		})
	}
}
func TestParentSwapDuringDirectoryOpen(t *testing.T) {
	f := newDescriptorFixture(t)
	factory := func() (sourceProvider, error) {
		p, err := f.factory()
		if err != nil {
			return nil, err
		}
		lp := p.(*linuxProvider)
		base := lp.openAt
		lp.openAt = func(parent int, name string, flags int) (int, error) {
			fd, err := base(parent, name, flags)
			if name == "etc" && err == nil {
				f.rename("etc", "saved-etc")
				f.mkdir("etc")
				f.write("etc/os-release", releaseText)
			}
			return fd, err
		}
		return p, nil
	}
	s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, factory)
	if err != nil {
		t.Fatal(err)
	}
	assertUnavailable(t, s, true, linuxpackages.ReasonSourceChanged)
}
