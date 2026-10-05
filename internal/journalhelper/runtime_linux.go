//go:build linux

package journalhelper

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/journalactivation"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalview"
)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

// Run consumes only the two fixed root-protected declarations and exactly one
// systemd-passed AF_UNIX listener. It never reads enrollment config or keys,
// creates/chmods sockets, changes identity/groups or installs host resources.
// Starting this real runtime/source still requires a separately approved local
// journal-content grant and installation. Synthetic tests never call Run.
func Run(ctx context.Context) error {
	i, e := processIdentity()
	if e != nil || !validID(i.RealUID) || !validID(i.EffectiveUID) || !validID(i.SavedUID) || !i.NoCapabilities {
		return ErrRejected
	}
	initial, e := loadState()
	if e != nil || validateState(initial, i) != nil {
		return ErrRejected
	}
	l, e := inheritedListener(initial.Deployment)
	if e != nil {
		return ErrRejected
	}
	defer l.Close()
	s, e := New(Dependencies{Load: loadState, Identity: processIdentity, Peer: peerIdentity, Capture: journalview.Collect, Now: func() time.Time { return time.Now().UTC() }})
	if e != nil {
		return ErrRejected
	}
	return s.Serve(ctx, l)
}
func processIdentity() (Identity, error) {
	r, e, s := unix.Getresuid()
	rg, eg, sg := unix.Getresgid()
	groups, err := unix.Getgroups()
	if err != nil {
		return Identity{}, ErrRejected
	}
	// Capget checks all permitted/effective/inheritable words; ambient/bounding
	// capabilities are additionally bounded away by the required hardened unit.
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if unix.Capget(&header, &caps[0]) != nil {
		return Identity{}, ErrRejected
	}
	noCaps := caps == [2]unix.CapUserData{}
	ids := make([]uint32, len(groups))
	for n, g := range groups {
		if g < 0 {
			return Identity{}, ErrRejected
		}
		ids[n] = uint32(g)
	}
	return Identity{RealUID: uint32(r), EffectiveUID: uint32(e), SavedUID: uint32(s), RealGID: uint32(rg), EffectiveGID: uint32(eg), SavedGID: uint32(sg), Groups: ids, NoCapabilities: noCaps}, nil
}
func peerIdentity(c net.Conn) (Peer, error) {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, ErrRejected
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return Peer{}, ErrRejected
	}
	var cred *unix.Ucred
	var inner error
	if raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || inner != nil || cred == nil {
		return Peer{}, ErrRejected
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
func safeDirectory(st unix.Stat_t) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0022 == 0 && st.Mode&(unix.S_ISUID|unix.S_ISGID) == 0
}
func protectedDirectory(parts []string) (int, error) {
	fd, e := unix.Open("/", directoryFlags, 0)
	if e != nil {
		return -1, ErrRejected
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !safeDirectory(st) {
		unix.Close(fd)
		return -1, ErrRejected
	}
	for _, name := range parts {
		next, e := unix.Openat(fd, name, directoryFlags, 0)
		unix.Close(fd)
		if e != nil {
			return -1, ErrRejected
		}
		fd = next
		if unix.Fstat(fd, &st) != nil || !safeDirectory(st) {
			unix.Close(fd)
			return -1, ErrRejected
		}
	}
	return fd, nil
}

// Rewalk the fixed path after a multi-file read. The pinned directory must
// still be the same protected directory at that path; root replacement or
// permission changes cannot leave a detached old policy authoritative.
func currentDirectory(fd int, parts []string) bool {
	next, e := protectedDirectory(parts)
	if e != nil {
		return false
	}
	defer unix.Close(next)
	var old, current unix.Stat_t
	return unix.Fstat(fd, &old) == nil && unix.Fstat(next, &current) == nil && safeDirectory(old) && sameObject(old, current)
}
func safeFile(st unix.Stat_t, max int) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0640 && st.Nlink == 1 && st.Size > 0 && st.Size <= int64(max)
}
func sameObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func protectedRead(dir int, name string, max int) ([]byte, unix.Stat_t, error) {
	fd, e := unix.Openat(dir, name, fileFlags, 0)
	if e != nil {
		return nil, unix.Stat_t{}, ErrRejected
	}
	f := os.NewFile(uintptr(fd), "journal-helper-policy")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !safeFile(before, max) {
		return nil, unix.Stat_t{}, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max || int64(len(b)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(dir, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameObject(before, after) || !sameObject(after, named) {
		return nil, unix.Stat_t{}, ErrRejected
	}
	return b, after, nil
}
func socketMetadata(d Deployment) (unix.Stat_t, error) {
	fd, e := protectedDirectory([]string{"run", "tracebolt-journal-reader"})
	if e != nil {
		return unix.Stat_t{}, ErrRejected
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstatat(fd, "reader.sock", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !safeSocket(st, d) {
		return unix.Stat_t{}, ErrRejected
	}
	return st, nil
}
func safeSocket(st unix.Stat_t, d Deployment) bool {
	return st.Uid == 0 && st.Gid == d.AgentGID && st.Mode&unix.S_IFMT == unix.S_IFSOCK && st.Mode&07777 == 0660 && st.Nlink == 1
}
func loadState() (State, error) {
	fd, e := protectedDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		return State{}, ErrRejected
	}
	defer unix.Close(fd)
	activation, present, activationRevision, ae := journalactivation.Read()
	if ae != nil || !journalactivation.Gate(activation, present, false) {
		return State{}, ErrRejected
	}
	deploymentRaw, ds, e := protectedRead(fd, "journal-helper.json", MaxDeploymentBytes)
	if e != nil {
		return State{}, ErrRejected
	}
	d, e := decodeDeployment(deploymentRaw)
	if e != nil || ds.Gid != d.HelperGID {
		return State{}, ErrRejected
	}
	policyRaw, ps, e := protectedRead(fd, "journal-content-policy.json", journalpolicy.MaxPolicyBytes)
	if e != nil || ps.Gid != d.HelperGID {
		return State{}, ErrRejected
	}
	p, e := journalpolicy.Decode(policyRaw)
	if e != nil || p.HelperUID != d.HelperUID || p.AgentUID != d.AgentUID {
		return State{}, ErrRejected
	}
	generation, ge := journalpolicy.PolicyGeneration(p)
	if ge != nil {
		return State{}, ErrRejected
	}
	if p.SchemaVersion == journalpolicy.Version {
		if present || d.SchemaVersion != DeploymentVersion || d.PolicyGenerationRequired {
			return State{}, ErrRejected
		}
	} else if !present || activation.SenderBinding != p.SenderBinding || activation.PolicyGeneration != generation || d.SchemaVersion != DeploymentVersionV2 || !d.PolicyGenerationRequired {
		return State{}, ErrRejected
	}
	sock, e := socketMetadata(d)
	if e != nil {
		return State{}, ErrRejected
	}
	// Reread the named metadata after both files: reject a cross-file replacement
	// during loading, including unchanged contents with changed owner/mode/inode.
	var dsNow, psNow unix.Stat_t
	if unix.Fstatat(fd, "journal-helper.json", &dsNow, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstatat(fd, "journal-content-policy.json", &psNow, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameObject(ds, dsNow) || !sameObject(ps, psNow) || !currentDirectory(fd, []string{"etc", "tracebolt"}) {
		return State{}, ErrRejected
	}
	// Stat fields have a stable local encoding. These bytes never leave the
	// process; only their revision hash is returned. Atime is intentionally absent.
	metadata := func(s unix.Stat_t) []byte {
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
		}{uint64(s.Dev), uint64(s.Ino), s.Uid, s.Gid, s.Mode, uint64(s.Nlink), s.Size, s.Mtim.Sec, s.Mtim.Nsec, s.Ctim.Sec, s.Ctim.Nsec})
		return b
	}
	again, presentAgain, activationAgain, err := journalactivation.Read()
	if err != nil || presentAgain != present || again != activation || activationAgain != activationRevision {
		return State{}, ErrRejected
	}
	return State{Policy: p, Deployment: d, PolicyGeneration: generation, Revision: revision(deploymentRaw, policyRaw, metadata(ds), metadata(ps), metadata(sock), []byte(activationRevision))}, nil
}
func inheritedListener(d Deployment) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "journal-reader" {
		return nil, ErrRejected
	}
	// Do not derive any path or descriptor from caller-controlled strings.
	const fd = 3
	if t, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); e != nil || t != unix.SOCK_STREAM {
		return nil, ErrRejected
	}
	if a, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); e != nil || a != 1 {
		return nil, ErrRejected
	}
	a, e := unix.Getsockname(fd)
	u, ok := a.(*unix.SockaddrUnix)
	if e != nil || !ok || u.Name != SocketPath {
		return nil, ErrRejected
	}
	if _, e = socketMetadata(d); e != nil {
		return nil, ErrRejected
	}
	f := os.NewFile(fd, "journal-reader-listener")
	if f == nil {
		return nil, ErrRejected
	}
	l, e := net.FileListener(f)
	f.Close()
	if e != nil {
		return nil, ErrRejected
	}
	ulistener, ok := l.(*net.UnixListener)
	if !ok {
		l.Close()
		return nil, ErrRejected
	}
	ulistener.SetUnlinkOnClose(false)
	return ulistener, nil
}
