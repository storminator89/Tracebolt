//go:build linux

package actionhelper

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"localrmm/internal/actionpermit"
)

const (
	authorityDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	authorityFileFlags      = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	maxPinnedInputBytes     = 32 << 20
)

// The production entry points always use / and UID 0. The private value form
// permits ordinary-user fixture trees without an environment, CLI or IPC switch
// that could substitute another authority root in production.
type authorityFS struct {
	root  string
	owner uint32
}

type authorityDirectory struct {
	fd   int
	stat unix.Stat_t
}

type authorityDirectories struct {
	fs    authorityFS
	parts []string
	dirs  []authorityDirectory
}

type authorityFile struct {
	file *os.File
	dir  int
	name string
	stat unix.Stat_t
	raw  []byte
}

func rootIDs(realUID, effectiveUID, savedUID, realGID, effectiveGID, savedGID int) bool {
	return realUID == 0 && effectiveUID == 0 && savedUID == 0 && realGID == 0 && effectiveGID == 0 && savedGID == 0
}

// Check the real, effective and saved identities independently. A setuid-only
// invocation or a root UID with an untrusted primary GID is not this helper.
func rootIdentity() error {
	r, e, s := unix.Getresuid()
	rg, eg, sg := unix.Getresgid()
	if !rootIDs(r, e, s, rg, eg, sg) {
		return ErrRejected
	}
	return nil
}

func safeAuthorityDirectory(st unix.Stat_t, owner uint32) bool {
	return st.Uid == owner && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0022 == 0 && st.Mode&(unix.S_ISUID|unix.S_ISGID) == 0
}

func sameAuthorityObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func authorityPathParts(p string) ([]string, error) {
	if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || len(p) > 512 || strings.ContainsAny(p, "\x00\r\n\t ") {
		return nil, ErrRejected
	}
	if p == "/" {
		return nil, nil
	}
	return strings.Split(p[1:], "/"), nil
}

// Keep every ancestor descriptor, not only the final directory. The second
// walk checks the same path names, while fstat checks the still-open originals.
func (fs authorityFS) openDirectories(p string) (*authorityDirectories, error) {
	parts, err := authorityPathParts(p)
	if err != nil {
		return nil, ErrRejected
	}
	d := &authorityDirectories{fs: fs, parts: parts}
	fd, err := unix.Open(fs.root, authorityDirectoryFlags, 0)
	if err != nil {
		return nil, ErrRejected
	}
	for n := 0; ; n++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !safeAuthorityDirectory(st, fs.owner) {
			unix.Close(fd)
			d.close()
			return nil, ErrRejected
		}
		d.dirs = append(d.dirs, authorityDirectory{fd: fd, stat: st})
		if n == len(parts) {
			return d, nil
		}
		fd, err = unix.Openat(fd, parts[n], authorityDirectoryFlags, 0)
		if err != nil {
			d.close()
			return nil, ErrRejected
		}
	}
}

func (d *authorityDirectories) close() {
	for _, dir := range d.dirs {
		unix.Close(dir.fd)
	}
	d.dirs = nil
}

func (d *authorityDirectories) fd() int { return d.dirs[len(d.dirs)-1].fd }

func (d *authorityDirectories) unchanged() bool {
	current, err := d.fs.openDirectories("/" + strings.Join(d.parts, "/"))
	if err != nil {
		return false
	}
	defer current.close()
	if len(d.dirs) != len(current.dirs) {
		return false
	}
	for n, dir := range d.dirs {
		var held unix.Stat_t
		if unix.Fstat(dir.fd, &held) != nil || !sameAuthorityObject(dir.stat, held) || !sameAuthorityObject(held, current.dirs[n].stat) {
			return false
		}
	}
	return true
}

func safeAuthorityFile(st unix.Stat_t, owner uint32, max int, strict bool) bool {
	if st.Uid != owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > int64(max) {
		return false
	}
	if strict {
		return st.Mode&07777 == 0600 && st.Size > 0
	}
	// Reviewed unit/configuration/executable inputs may be readable or executable
	// by the agent, but must never be writable by it or carry set-ID bits.
	return st.Mode&0022 == 0 && st.Mode&(unix.S_ISUID|unix.S_ISGID) == 0
}

func (d *authorityDirectories) readFile(name string, max int, strict bool) (*authorityFile, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || max < 1 {
		return nil, ErrRejected
	}
	fd, err := unix.Openat(d.fd(), name, authorityFileFlags, 0)
	if err != nil {
		return nil, ErrRejected
	}
	f := &authorityFile{file: os.NewFile(uintptr(fd), "action-helper-protected-input"), dir: d.fd(), name: name}
	if unix.Fstat(fd, &f.stat) != nil || !safeAuthorityFile(f.stat, d.fs.owner, max, strict) {
		f.close()
		return nil, ErrRejected
	}
	f.raw, err = io.ReadAll(io.LimitReader(f.file, int64(max)+1))
	if err != nil || len(f.raw) > max || int64(len(f.raw)) != f.stat.Size || !f.unchanged() {
		f.close()
		return nil, ErrRejected
	}
	return f, nil
}

func (f *authorityFile) close() { f.file.Close() }

func (f *authorityFile) unchanged() bool {
	var held, named unix.Stat_t
	return unix.Fstat(int(f.file.Fd()), &held) == nil && unix.Fstatat(f.dir, f.name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil && sameAuthorityObject(f.stat, held) && sameAuthorityObject(held, named)
}

// Encode only stable metadata. Atime can change because of the read itself;
// ctime/mtime, ownership, type/mode, link count and object identity cannot.
func authorityMetadata(s unix.Stat_t) []byte {
	b, _ := json.Marshal(struct {
		Dev      uint64
		Ino      uint64
		UID      uint32
		GID      uint32
		Mode     uint32
		Links    uint64
		Size     int64
		MtimeSec int64
		MtimeNS  int64
		CtimeSec int64
		CtimeNS  int64
	}{uint64(s.Dev), uint64(s.Ino), s.Uid, s.Gid, s.Mode, uint64(s.Nlink), s.Size, int64(s.Mtim.Sec), int64(s.Mtim.Nsec), int64(s.Ctim.Sec), int64(s.Ctim.Nsec)})
	return b
}

func authorityRevision(d *authorityDirectories, policy, key *authorityFile) string {
	metadata := make([][]byte, 0, len(d.dirs)+2)
	for _, dir := range d.dirs {
		metadata = append(metadata, authorityMetadata(dir.stat))
	}
	metadata = append(metadata, authorityMetadata(policy.stat), authorityMetadata(key.stat))
	b, _ := json.Marshal(struct {
		Domain   string
		Policy   []byte
		Key      []byte
		Metadata [][]byte
	}{"tracebolt.action-helper-authority.v1", policy.raw, key.raw, metadata})
	return actionpermit.Digest(b)
}

func loadAuthority() (Authority, error) {
	if rootIdentity() != nil {
		return Authority{}, ErrRejected
	}
	return loadAuthorityFrom(authorityFS{root: "/", owner: 0})
}

func loadAuthorityFrom(fs authorityFS) (Authority, error) {
	// These constants cannot be overridden by a permit, socket request or env.
	if path.Dir(PolicyPath) != path.Dir(PublicKeyPath) {
		return Authority{}, ErrRejected
	}
	d, err := fs.openDirectories(path.Dir(PolicyPath))
	if err != nil {
		return Authority{}, ErrRejected
	}
	defer d.close()
	policy, err := d.readFile(path.Base(PolicyPath), MaxPolicyBytes, true)
	if err != nil {
		return Authority{}, ErrRejected
	}
	defer policy.close()
	key, err := d.readFile(path.Base(PublicKeyPath), ed25519.PublicKeySize, true)
	if err != nil {
		return Authority{}, ErrRejected
	}
	defer key.close()
	if len(key.raw) != ed25519.PublicKeySize {
		return Authority{}, ErrRejected
	}
	p, err := decodePolicy(policy.raw, ed25519.PublicKey(key.raw))
	if err != nil || !d.unchanged() || !policy.unchanged() || !key.unchanged() {
		return Authority{}, ErrRejected
	}
	return Authority{Policy: p, PublicKey: ed25519.PublicKey(key.raw), Revision: authorityRevision(d, policy, key)}, nil
}

func checkPinnedInput(pin FilePin) error {
	if rootIdentity() != nil {
		return ErrRejected
	}
	return checkPinnedInputFrom(authorityFS{root: "/", owner: 0}, pin)
}

func checkPinnedInputFrom(fs authorityFS, pin FilePin) error {
	if !safeInputPath(pin.Path) || !actionpermit.ValidDigest(pin.Digest) {
		return ErrRejected
	}
	d, err := fs.openDirectories(path.Dir(pin.Path))
	if err != nil {
		return ErrRejected
	}
	defer d.close()
	f, err := d.readFile(path.Base(pin.Path), maxPinnedInputBytes, false)
	if err != nil {
		return ErrRejected
	}
	defer f.close()
	if actionpermit.Digest(f.raw) != pin.Digest || !d.unchanged() || !f.unchanged() {
		return ErrRejected
	}
	return nil
}

func peerIdentity(c net.Conn) (Peer, error) {
	u, ok := c.(*net.UnixConn)
	if !ok || u == nil {
		return Peer{}, ErrRejected
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return Peer{}, ErrRejected
	}
	var cred *unix.Ucred
	var inner error
	if raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || inner != nil || cred == nil || cred.Pid <= 0 {
		return Peer{}, ErrRejected
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

func safeAuthoritySocket(st unix.Stat_t, owner, group uint32) bool {
	return st.Uid == owner && st.Gid == group && st.Mode&unix.S_IFMT == unix.S_IFSOCK && st.Mode&07777 == 0660 && st.Nlink == 1
}

func inheritedListener(p Policy) (net.Listener, error) {
	if rootIdentity() != nil {
		return nil, ErrRejected
	}
	listener, err := inheritedListenerFrom(p, authorityFS{root: "/", owner: 0}, 3, SocketPath, os.Getenv, os.Getpid())
	if err == nil {
		unix.Close(3)
	}
	return listener, err
}

// The descriptor is fixed at 3 by the production wrapper. This private helper
// borrows it and returns an independent listener; the production wrapper closes
// the inherited descriptor after success. No socket is created or unlinked.
func inheritedListenerFrom(p Policy, fs authorityFS, fd int, socketPath string, getenv func(string) string, pid int) (net.Listener, error) {
	if getenv("LISTEN_PID") != strconv.Itoa(pid) || getenv("LISTEN_FDS") != "1" || getenv("LISTEN_FDNAMES") != "action-helper" {
		return nil, ErrRejected
	}
	if t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || t != unix.SOCK_STREAM {
		return nil, ErrRejected
	}
	if listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || listening != 1 {
		return nil, ErrRejected
	}
	addr, err := unix.Getsockname(fd)
	name, ok := addr.(*unix.SockaddrUnix)
	if err != nil || !ok || name.Name != socketPath {
		return nil, ErrRejected
	}
	d, err := fs.openDirectories(path.Dir(SocketPath))
	if err != nil {
		return nil, ErrRejected
	}
	defer d.close()
	var before unix.Stat_t
	if unix.Fstatat(d.fd(), path.Base(SocketPath), &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !safeAuthoritySocket(before, fs.owner, p.AgentGID) {
		return nil, ErrRejected
	}
	copyFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRejected
	}
	f := os.NewFile(uintptr(copyFD), "action-helper-listener")
	listener, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, ErrRejected
	}
	u, ok := listener.(*net.UnixListener)
	if !ok {
		listener.Close()
		return nil, ErrRejected
	}
	u.SetUnlinkOnClose(false)
	var after unix.Stat_t
	if unix.Fstatat(d.fd(), path.Base(SocketPath), &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameAuthorityObject(before, after) || !d.unchanged() {
		u.Close()
		return nil, ErrRejected
	}
	return u, nil
}
