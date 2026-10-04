//go:build linux

package packagecollector

import (
	"errors"
	"io"
	"localrmm/internal/linuxpackages"

	"golang.org/x/sys/unix"
)

const directoryFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
const probeFlags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
const readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

type rootOpener func() (int, error)
type linuxProvider struct {
	root       *pinnedNode
	uid        uint32
	reopenRoot rootOpener
	openAt     func(int, string, int) (int, error)
}
type pinnedNode struct {
	fd        int
	parent    int
	name      string
	before    unix.Stat_t
	directory bool
	link      string
}
type linuxSource struct {
	provider      *linuxProvider
	nodes         []*pinnedNode
	fd            int
	before        unix.Stat_t
	missingParent int
	missingName   string
}

func newSystemProvider() (sourceProvider, error) {
	return newLinuxProvider(func() (int, error) { return unix.Open("/", directoryFlags, 0) }, 0)
}

// The explicit private opener/owner seam is used only with disposable fixture
// roots. Production always opens '/' and requires UID 0. No public path/root
// configuration or mutable global opener is available.
func newLinuxProvider(openRoot rootOpener, uid uint32) (sourceProvider, error) {
	fd, err := openRoot()
	if err != nil {
		return nil, osFailure(err)
	}
	stat, err := descriptorStat(fd)
	if err != nil || !trustedDirectory(stat, uid) {
		unix.Close(fd)
		if err != nil {
			return nil, osFailure(err)
		}
		return nil, sourceFailure(linuxpackages.ReasonInvalidSource)
	}
	return &linuxProvider{root: &pinnedNode{fd: fd, before: stat, directory: true}, uid: uid, reopenRoot: openRoot,
		openAt: func(parent int, name string, flags int) (int, error) { return unix.Openat(parent, name, flags, 0) }}, nil
}
func (p *linuxProvider) close() { unix.Close(p.root.fd) }

func (p *linuxProvider) open(kind sourceKind) (source, error) {
	s := &linuxSource{provider: p, fd: -1, missingParent: -1}
	var err error
	switch kind {
	case releaseSource:
		err = s.openRelease()
	case inventorySource:
		var parent int
		parent, err = s.walk("var", "lib", "dpkg")
		if err == nil {
			err = s.openRegular(parent, "status", linuxpackages.MaxDpkgBytes)
		}
	default:
		err = sourceFailure(linuxpackages.ReasonInvalidSource)
	}
	if err == nil {
		err = s.recheck()
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}
func (s *linuxSource) openRelease() error {
	etc, err := s.walk("etc")
	if err != nil {
		return err
	}
	leaf, err := s.probe(etc, "os-release")
	if err != nil {
		// No fallback is permitted unless this exact leaf is ENOENT after the
		// protected /etc directory was successfully pinned and validated.
		if !errors.Is(err, unix.ENOENT) {
			return osFailure(err)
		}
		s.missingParent, s.missingName = etc, "os-release"
		target, err := s.walk("usr", "lib")
		if err != nil {
			return err
		}
		return s.openRegular(target, "os-release", linuxpackages.MaxOSReleaseBytes)
	}
	switch leaf.before.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return s.readRegular(leaf, linuxpackages.MaxOSReleaseBytes)
	case unix.S_IFLNK:
		if leaf.before.Uid != s.provider.uid {
			return sourceFailure(linuxpackages.ReasonInvalidSource)
		}
		link, err := readLink(leaf.fd, "")
		if err != nil {
			return osFailure(err)
		}
		if link != "../usr/lib/os-release" && link != "/usr/lib/os-release" {
			return sourceFailure(linuxpackages.ReasonInvalidSource)
		}
		leaf.link = link
		target, err := s.walk("usr", "lib")
		if err != nil {
			return err
		}
		return s.openRegular(target, "os-release", linuxpackages.MaxOSReleaseBytes)
	default:
		return sourceFailure(linuxpackages.ReasonInvalidSource)
	}
}
func (s *linuxSource) walk(components ...string) (int, error) {
	parent := s.provider.root.fd
	for _, name := range components {
		fd, err := s.provider.openAt(parent, name, directoryFlags)
		if err != nil {
			return -1, osFailure(err)
		}
		st, err := descriptorStat(fd)
		if err != nil || !trustedDirectory(st, s.provider.uid) {
			unix.Close(fd)
			if err != nil {
				return -1, osFailure(err)
			}
			return -1, sourceFailure(linuxpackages.ReasonInvalidSource)
		}
		node := &pinnedNode{fd: fd, parent: parent, name: name, before: st, directory: true}
		s.nodes = append(s.nodes, node)
		if err := node.recheck(); err != nil {
			return -1, err
		}
		parent = fd
	}
	return parent, nil
}
func (s *linuxSource) probe(parent int, name string) (*pinnedNode, error) {
	fd, err := s.provider.openAt(parent, name, probeFlags)
	if err != nil {
		return nil, err
	}
	st, err := descriptorStat(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	node := &pinnedNode{fd: fd, parent: parent, name: name, before: st}
	s.nodes = append(s.nodes, node)
	return node, nil
}
func (s *linuxSource) openRegular(parent int, name string, cap int64) error {
	node, err := s.probe(parent, name)
	if err != nil {
		return osFailure(err)
	}
	return s.readRegular(node, cap)
}
func (s *linuxSource) readRegular(node *pinnedNode, cap int64) error {
	st := node.before
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != s.provider.uid || st.Mode&0022 != 0 || st.Size < 0 || st.Size > cap {
		return sourceFailure(linuxpackages.ReasonInvalidSource)
	}
	fd, err := s.provider.openAt(node.parent, node.name, readFlags)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) {
			return sourceFailure(linuxpackages.ReasonSourceChanged)
		}
		return osFailure(err)
	}
	s.fd = fd
	after, err := descriptorStat(fd)
	if err != nil {
		return osFailure(err)
	}
	if !sameFile(st, after) {
		return sourceFailure(linuxpackages.ReasonSourceChanged)
	}
	s.before = after
	return nil
}
func (s *linuxSource) Read(p []byte) (int, error) {
	n, err := unix.Read(s.fd, p)
	if n < 0 {
		n = 0
	}
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}
func (s *linuxSource) close() {
	if s.fd >= 0 {
		unix.Close(s.fd)
		s.fd = -1
	}
	for i := len(s.nodes) - 1; i >= 0; i-- {
		unix.Close(s.nodes[i].fd)
	}
	s.nodes = nil
}
func (s *linuxSource) recheck() error {
	p := s.provider
	now, err := descriptorStat(p.root.fd)
	if err != nil || !sameDirectory(p.root.before, now) {
		return changed()
	}
	current, err := p.reopenRoot()
	if err != nil {
		return changed()
	}
	rootNow, err := descriptorStat(current)
	unix.Close(current)
	if err != nil || !sameDirectory(p.root.before, rootNow) {
		return changed()
	}
	for _, node := range s.nodes {
		if err := node.recheck(); err != nil {
			return err
		}
	}
	if s.missingParent >= 0 {
		var st unix.Stat_t
		if err := unix.Fstatat(s.missingParent, s.missingName, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return changed()
		}
	}
	now, err = descriptorStat(s.fd)
	if err != nil || !sameFile(s.before, now) {
		return changed()
	}
	return nil
}
func (n *pinnedNode) recheck() error {
	descriptor, err := descriptorStat(n.fd)
	if err != nil {
		return changed()
	}
	var path unix.Stat_t
	if err := unix.Fstatat(n.parent, n.name, &path, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return changed()
	}
	same := sameFile
	if n.directory {
		same = sameDirectory
	}
	if !same(n.before, descriptor) || !same(n.before, path) {
		return changed()
	}
	if n.link != "" {
		pinnedLink, err := readLink(n.fd, "")
		if err != nil || pinnedLink != n.link {
			return changed()
		}
		currentLink, err := readLink(n.parent, n.name)
		if err != nil || currentLink != n.link {
			return changed()
		}
	}
	return nil
}
func descriptorStat(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	return st, err
}
func trustedDirectory(st unix.Stat_t, uid uint32) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == uid && st.Mode&0022 == 0
}
func sameDirectory(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink
}
func sameFile(a, b unix.Stat_t) bool {
	return sameDirectory(a, b) && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func readLink(parent int, name string) (string, error) {
	var buf [64]byte
	n, err := unix.Readlinkat(parent, name, buf[:])
	if err != nil {
		return "", err
	}
	if n == len(buf) {
		return "", sourceFailure(linuxpackages.ReasonInvalidSource)
	}
	return string(buf[:n]), nil
}
func changed() error { return sourceFailure(linuxpackages.ReasonSourceChanged) }
func osFailure(err error) error {
	var failure sourceFailure
	if errors.As(err, &failure) {
		return failure
	}
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return sourceFailure(linuxpackages.ReasonPermissionDenied)
	case errors.Is(err, unix.ENOENT):
		return sourceFailure(linuxpackages.ReasonSourceMissing)
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return sourceFailure(linuxpackages.ReasonInvalidSource)
	default:
		return sourceFailure(linuxpackages.ReasonReadFailed)
	}
}
