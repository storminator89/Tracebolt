//go:build darwin

package macosservice

import (
	"golang.org/x/sys/unix"
	"localrmm/internal/darwinprotect"
	"os"
	"path"
	"strings"
)

type heldNode struct {
	fd   int
	name string
	stat unix.Stat_t
}
type protectedPath struct {
	nodes []heldNode
	file  *os.File
}

func (p *protectedPath) close() {
	if p == nil {
		return
	}
	for i := len(p.nodes) - 1; i >= 0; i-- {
		_ = unix.Close(p.nodes[i].fd)
	}
	p.nodes = nil
}
func sameNode(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Flags == b.Flags
}
func (p *protectedPath) stable() bool {
	if p == nil || len(p.nodes) == 0 {
		return false
	}
	for i, n := range p.nodes {
		var now, entry unix.Stat_t
		if darwinprotect.Fstat(n.fd, &now) != nil || !sameNode(n.stat, now) {
			return false
		}
		if i > 0 && (unix.Fstatat(p.nodes[i-1].fd, n.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameNode(now, entry)) {
			return false
		}
	}
	return true
}

// Every component is descriptor-anchored, symlink-free, local, ACL-checked and
// root-owned except the exact fixed private state subtree. No chmod/chown, alias
// resolution, directory creation or private-state initialization is available.
func openProtected(name string, directory bool, uid, gid int, executable bool, limit int64) (*protectedPath, error) {
	if !path.IsAbs(name) || path.Clean(name) != name || name == "/" || strings.ContainsRune(name, 0) {
		return nil, ErrPreflight
	}
	p := &protectedPath{}
	fail := func() (*protectedPath, error) { p.close(); return nil, ErrPreflight }
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPreflight
	}
	p.nodes = append(p.nodes, heldNode{fd: fd})
	if darwinprotect.Fstat(fd, &p.nodes[0].stat) != nil || !safeDirectory("/", p.nodes[0].stat, uid, gid) {
		return fail()
	}
	components := strings.Split(strings.TrimPrefix(name, "/"), "/")
	current := ""
	for i, component := range components {
		current += "/" + component
		last := i == len(components)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if !last || directory {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, component, flags, 0)
		if err != nil {
			return fail()
		}
		p.nodes = append(p.nodes, heldNode{fd: next, name: component})
		n := &p.nodes[len(p.nodes)-1]
		if darwinprotect.Fstat(next, &n.stat) != nil {
			return fail()
		}
		if !last || directory {
			if !safeDirectory(current, n.stat, uid, gid) {
				return fail()
			}
		} else {
			st := n.stat
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&07022 != 0 || st.Size < 1 || st.Size > limit || executable && st.Mode&0111 != 0111 {
				return fail()
			}
		}
		fd = next
	}
	if !p.stable() {
		return fail()
	}
	if !directory {
		// os.File owns the final descriptor. Remove it from close's raw-close set,
		// but retain it in the snapshot until the caller has revalidated the chain.
		p.file = os.NewFile(uintptr(fd), "reviewed-macos-service-artifact")
	}
	return p, nil
}
func (p *protectedPath) closeArtifact() {
	if p != nil && p.file != nil {
		_ = p.file.Close()
		p.file = nil
		// Avoid double-closing a descriptor that the runtime may reuse.
		p.nodes = p.nodes[:len(p.nodes)-1]
	}
	p.close()
}
func safeDirectory(name string, st unix.Stat_t, uid, gid int) bool {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 || st.Mode&07022 != 0 {
		return false
	}
	if name == StateDirectory || strings.HasPrefix(name, StateDirectory+"/") {
		return st.Uid == uint32(uid) && st.Gid == uint32(gid) && st.Mode&0777 == 0700
	}
	return st.Uid == 0
}
