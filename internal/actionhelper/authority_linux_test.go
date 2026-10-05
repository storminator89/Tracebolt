//go:build linux

package actionhelper

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/actionpermit"
)

// All filesystem fixtures live in ordinary-user temporary directories. Nothing
// calls the production loader, opens production authority paths, changes host
// ownership, executes systemctl or changes process credentials.
func authorityFixture(t testing.TB) (authorityFS, Policy, []byte) {
	t.Helper()
	fs := authorityFS{root: t.TempDir(), owner: uint32(os.Getuid())}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	p := Policy{
		Version: PolicyVersion, Enabled: true,
		ManagerID: "manager_" + strings.Repeat("1", 32), KeyID: actionpermit.Digest(key),
		EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: actionpermit.Digest([]byte("fixture incarnation")),
		TransportProfile: ProductionTLS, AgentUID: 1201, AgentGID: 1201,
		MaxLifetimeSeconds: 90, MaxFutureSkewSeconds: 2,
		Targets: []Target{{
			Unit: "fixture.service", ReviewDigest: actionpermit.Digest([]byte("fixture review")),
			Units:  []UnitPin{{Unit: "fixture.service", ConfigurationDigest: actionpermit.Digest([]byte("fixture unit"))}},
			Inputs: []FilePin{{Path: "/etc/fixture.conf", Digest: actionpermit.Digest([]byte("fixture input"))}},
		}},
	}
	if err := os.MkdirAll(filepath.Join(fs.root, "etc", "tracebolt"), 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	authorityWrite(t, fs.root+PolicyPath, raw, 0600)
	authorityWrite(t, fs.root+PublicKeyPath, key, 0600)
	return fs, p, key
}

func authorityWrite(t testing.TB, name string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(name, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityRootIdentities(t *testing.T) {
	if !rootIDs(0, 0, 0, 0, 0, 0) {
		t.Fatal("root identity rejected")
	}
	for n := range 6 {
		ids := [6]int{}
		ids[n] = 1200
		if rootIDs(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]) {
			t.Fatalf("non-root identity %d accepted", n)
		}
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		if rootIdentity() == nil {
			t.Fatal("ordinary-user helper identity accepted")
		}
	}
}

func TestAuthorityMetadataPredicates(t *testing.T) {
	const owner = 1200
	dir := unix.Stat_t{Uid: owner, Mode: unix.S_IFDIR | 0755}
	if !safeAuthorityDirectory(dir, owner) {
		t.Fatal("protected fixture directory rejected")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Mode |= 0020 },
		func(s *unix.Stat_t) { s.Mode |= 0002 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0755 },
		func(s *unix.Stat_t) { s.Mode |= unix.S_ISUID }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISGID },
	} {
		s := dir
		mutate(&s)
		if safeAuthorityDirectory(s, owner) {
			t.Fatal("unsafe directory accepted")
		}
	}
	file := unix.Stat_t{Uid: owner, Mode: unix.S_IFREG | 0600, Nlink: 1, Size: 32}
	if !safeAuthorityFile(file, owner, 32, true) {
		t.Fatal("protected fixture file rejected")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0600 },
		func(s *unix.Stat_t) { s.Mode |= 0040 }, func(s *unix.Stat_t) { s.Mode |= 0004 },
		func(s *unix.Stat_t) { s.Mode |= unix.S_ISUID }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISGID },
		func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Size = 0 },
		func(s *unix.Stat_t) { s.Size = -1 }, func(s *unix.Stat_t) { s.Size = 33 },
	} {
		s := file
		mutate(&s)
		if safeAuthorityFile(s, owner, 32, true) {
			t.Fatal("unsafe authority file accepted")
		}
	}
	for _, mode := range []uint32{0600, 0644, 0755} {
		s := file
		s.Mode = unix.S_IFREG | mode
		s.Size = maxPinnedInputBytes
		if !safeAuthorityFile(s, owner, maxPinnedInputBytes, false) {
			t.Fatalf("protected input mode %o rejected", mode)
		}
	}
	for _, mode := range []uint32{0664, 0666, 0775, 04755, 02755} {
		s := file
		s.Mode = unix.S_IFREG | mode
		if safeAuthorityFile(s, owner, 32, false) {
			t.Fatalf("unsafe input mode %o accepted", mode)
		}
	}
	socket := unix.Stat_t{Uid: owner, Gid: 1201, Mode: unix.S_IFSOCK | 0660, Nlink: 1}
	if !safeAuthoritySocket(socket, owner, 1201) {
		t.Fatal("protected fixture socket rejected")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Gid++ },
		func(s *unix.Stat_t) { s.Mode |= 0002 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0660 },
		func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISGID },
	} {
		s := socket
		mutate(&s)
		if safeAuthoritySocket(s, owner, 1201) {
			t.Fatal("unsafe socket accepted")
		}
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Dev++ }, func(s *unix.Stat_t) { s.Ino++ },
		func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Gid++ },
		func(s *unix.Stat_t) { s.Mode++ }, func(s *unix.Stat_t) { s.Nlink++ },
		func(s *unix.Stat_t) { s.Size++ }, func(s *unix.Stat_t) { s.Mtim.Nsec++ }, func(s *unix.Stat_t) { s.Ctim.Nsec++ },
	} {
		s := file
		mutate(&s)
		if sameAuthorityObject(file, s) || bytes.Equal(authorityMetadata(file), authorityMetadata(s)) {
			t.Fatal("changed authority metadata accepted")
		}
	}
	atime := file
	atime.Atim.Nsec++
	if !sameAuthorityObject(file, atime) || !bytes.Equal(authorityMetadata(file), authorityMetadata(atime)) {
		t.Fatal("access time incorrectly changes authority")
	}
}

func TestAuthorityFixtureLoadAndRevision(t *testing.T) {
	fs, p, key := authorityFixture(t)
	first, err := loadAuthorityFrom(fs)
	if err != nil || !bytes.Equal(first.PublicKey, key) || first.Policy.ManagerID != p.ManagerID || !actionpermit.ValidDigest(first.Revision) {
		t.Fatal("fixture authority load", err)
	}
	again, err := loadAuthorityFrom(fs)
	if err != nil || again.Revision != first.Revision {
		t.Fatal("unchanged fixture revision", err)
	}
	stamp := time.Unix(1600000000, 123)
	if err := os.Chtimes(fs.root+PublicKeyPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	changed, err := loadAuthorityFrom(fs)
	if err != nil || changed.Revision == first.Revision || !bytes.Equal(changed.PublicKey, key) {
		t.Fatal("key metadata not bound to authority revision", err)
	}
	replacement := fs.root + PublicKeyPath + ".replacement"
	authorityWrite(t, replacement, key, 0600)
	if err := os.Rename(replacement, fs.root+PublicKeyPath); err != nil {
		t.Fatal(err)
	}
	replaced, err := loadAuthorityFrom(fs)
	if err != nil || replaced.Revision == changed.Revision {
		t.Fatal("key inode replacement not bound to revision", err)
	}
	// Even a mode change on an ancestor retains no stale authority revision.
	if err := os.Chmod(filepath.Join(fs.root, "etc"), 0750); err != nil {
		t.Fatal(err)
	}
	dirChanged, err := loadAuthorityFrom(fs)
	if err != nil || dirChanged.Revision == replaced.Revision {
		t.Fatal("directory metadata not bound to revision", err)
	}
	p.Enabled = false
	raw, _ := json.Marshal(p)
	authorityWrite(t, fs.root+PolicyPath, raw, 0600)
	disabled, err := loadAuthorityFrom(fs)
	if err != nil || disabled.Policy.Enabled || disabled.Revision == dirChanged.Revision {
		t.Fatal("disabled policy must be readable for revocation checks", err)
	}
}

func TestAuthorityKeyEncodingAndPolicyCanonical(t *testing.T) {
	for _, size := range []int{0, 31, 33, 64} {
		t.Run("key_length_"+strconv.Itoa(size), func(t *testing.T) {
			fs, _, _ := authorityFixture(t)
			authorityWrite(t, fs.root+PublicKeyPath, bytes.Repeat([]byte{'x'}, size), 0600)
			if _, err := loadAuthorityFrom(fs); err == nil {
				t.Fatal("non-raw-32-byte key accepted")
			}
		})
	}
	t.Run("invalid_curve_key", func(t *testing.T) {
		fs, _, _ := authorityFixture(t)
		authorityWrite(t, fs.root+PublicKeyPath, make([]byte, 32), 0600)
		if _, err := loadAuthorityFrom(fs); err == nil {
			t.Fatal("invalid key accepted")
		}
	})
	for name, mutate := range map[string]func([]byte) []byte{
		"leading_space":     func(b []byte) []byte { return append([]byte{' '}, b...) },
		"two_newlines":      func(b []byte) []byte { return append(b, '\n', '\n') },
		"unknown_field":     func(b []byte) []byte { return append([]byte(`{"unknown":1,`), b[1:]...) },
		"duplicate_field":   func(b []byte) []byte { return append([]byte(`{"enabled":true,`), b[1:]...) },
		"case_folded_field": func(b []byte) []byte { return bytes.Replace(b, []byte(`"version"`), []byte(`"Version"`), 1) },
		"null_targets": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"targets":[`), []byte(`"targets":null,"extra":[`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fs, p, _ := authorityFixture(t)
			raw, _ := json.Marshal(p)
			authorityWrite(t, fs.root+PolicyPath, mutate(raw), 0600)
			if _, err := loadAuthorityFrom(fs); err == nil {
				t.Fatal("noncanonical policy accepted")
			}
		})
	}
	fs, p, _ := authorityFixture(t)
	raw, _ := json.Marshal(p)
	authorityWrite(t, fs.root+PolicyPath, append(raw, '\n'), 0600)
	if _, err := loadAuthorityFrom(fs); err != nil {
		t.Fatal("one optional final policy newline rejected", err)
	}
}

func TestAuthorityRejectsUnsafeFixtureFiles(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, authorityFS){
		"group_writable_ancestor": func(t *testing.T, fs authorityFS) { mustAuthorityChmod(t, fs.root+"/etc", 0770) },
		"world_writable_anchor":   func(t *testing.T, fs authorityFS) { mustAuthorityChmod(t, fs.root, 0702) },
		"readable_policy":         func(t *testing.T, fs authorityFS) { mustAuthorityChmod(t, fs.root+PolicyPath, 0644) },
		"readable_key":            func(t *testing.T, fs authorityFS) { mustAuthorityChmod(t, fs.root+PublicKeyPath, 0644) },
		"hardlinked_policy":       func(t *testing.T, fs authorityFS) { mustAuthorityLink(t, fs.root+PolicyPath, fs.root+"/policy-link") },
		"hardlinked_key":          func(t *testing.T, fs authorityFS) { mustAuthorityLink(t, fs.root+PublicKeyPath, fs.root+"/key-link") },
		"symlinked_policy":        func(t *testing.T, fs authorityFS) { authoritySymlinkReplacement(t, fs.root+PolicyPath) },
		"symlinked_key":           func(t *testing.T, fs authorityFS) { authoritySymlinkReplacement(t, fs.root+PublicKeyPath) },
		"symlinked_ancestor":      func(t *testing.T, fs authorityFS) { authoritySymlinkReplacement(t, fs.root+"/etc") },
		"oversized_policy": func(t *testing.T, fs authorityFS) {
			authorityWrite(t, fs.root+PolicyPath, bytes.Repeat([]byte{' '}, MaxPolicyBytes+1), 0600)
		},
		"fifo_policy": func(t *testing.T, fs authorityFS) {
			if err := os.Remove(fs.root + PolicyPath); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(fs.root+PolicyPath, 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fs, _, _ := authorityFixture(t)
			mutate(t, fs)
			if _, err := loadAuthorityFrom(fs); err == nil {
				t.Fatal("unsafe fixture accepted")
			}
		})
	}
	fs, _, _ := authorityFixture(t)
	fs.owner++ // Reject owner mismatch without any privileged fixture chown.
	if _, err := loadAuthorityFrom(fs); err == nil {
		t.Fatal("wrong root owner accepted")
	}
}

func mustAuthorityChmod(t *testing.T, name string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}
func mustAuthorityLink(t *testing.T, old, new string) {
	t.Helper()
	if err := os.Link(old, new); err != nil {
		t.Fatal(err)
	}
}
func authoritySymlinkReplacement(t *testing.T, name string) {
	t.Helper()
	if err := os.Rename(name, name+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(name+".real", name); err != nil {
		t.Fatal(err)
	}
}

func TestAuthoritySnapshotDetectsReplacementAndMutation(t *testing.T) {
	for _, which := range []string{"policy", "key", "directory", "ancestor", "metadata", "in_place"} {
		t.Run(which, func(t *testing.T) {
			fs, _, _ := authorityFixture(t)
			d, err := fs.openDirectories("/etc/tracebolt")
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			policy, err := d.readFile("action-helper.json", MaxPolicyBytes, true)
			if err != nil {
				t.Fatal(err)
			}
			defer policy.close()
			key, err := d.readFile("action-command.pub", 32, true)
			if err != nil {
				t.Fatal(err)
			}
			defer key.close()
			if !d.unchanged() || !policy.unchanged() || !key.unchanged() {
				t.Fatal("initial snapshots")
			}
			switch which {
			case "policy", "key":
				f, name := policy, fs.root+PolicyPath
				if which == "key" {
					f, name = key, fs.root+PublicKeyPath
				}
				authorityWrite(t, name+".new", f.raw, 0600)
				if err := os.Rename(name+".new", name); err != nil {
					t.Fatal(err)
				}
				if f.unchanged() {
					t.Fatal("same-content inode replacement accepted")
				}
			case "directory", "ancestor":
				name := fs.root + "/etc/tracebolt"
				if which == "ancestor" {
					name = fs.root + "/etc"
				}
				if err := os.Rename(name, name+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
				if d.unchanged() {
					t.Fatal("detached directory accepted")
				}
			case "metadata":
				mustAuthorityChmod(t, fs.root+PublicKeyPath, 0640)
				if key.unchanged() {
					t.Fatal("key mode mutation accepted")
				}
			case "in_place":
				changed := bytes.Clone(policy.raw)
				changed[0] = ' '
				authorityWrite(t, fs.root+PolicyPath, changed, 0600)
				if policy.unchanged() {
					t.Fatal("same-size mutation accepted")
				}
			}
			if d.unchanged() && policy.unchanged() && key.unchanged() {
				t.Fatal("cross-file snapshot changed without rejection")
			}
		})
	}
}

func TestAuthorityPinnedInputs(t *testing.T) {
	fs, _, _ := authorityFixture(t)
	for _, p := range []string{"/etc/fixture.conf", "/usr/lib/fixture", "/opt/app/config"} {
		if err := os.MkdirAll(filepath.Dir(fs.root+p), 0700); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []os.FileMode{0600, 0644, 0755} {
			raw := []byte("fixed reviewed fixture input")
			authorityWrite(t, fs.root+p, raw, mode)
			pin := FilePin{Path: p, Digest: actionpermit.Digest(raw)}
			if err := checkPinnedInputFrom(fs, pin); err != nil {
				t.Fatalf("%s %o: %v", p, mode, err)
			}
			pin.Digest = actionpermit.Digest([]byte("changed"))
			if checkPinnedInputFrom(fs, pin) == nil {
				t.Fatal("input digest mismatch accepted")
			}
		}
	}
	for _, p := range []string{"relative", "/etc/../etc/fixture.conf", "/etc//fixture.conf", "/etc/fixture.conf/", "/tmp/input", "/run/input", "/var/input", "/etc/space name", "/etc/tab\tname", "/etc/nul\x00name"} {
		if checkPinnedInputFrom(fs, FilePin{Path: p, Digest: actionpermit.Digest(nil)}) == nil {
			t.Fatalf("unsafe input path accepted: %q", p)
		}
	}
	for _, mode := range []os.FileMode{0664, 0666, 0775, os.ModeSetuid | 0755, os.ModeSetgid | 0755} {
		authorityWrite(t, fs.root+"/etc/fixture.conf", []byte("fixture"), mode)
		if checkPinnedInputFrom(fs, FilePin{Path: "/etc/fixture.conf", Digest: actionpermit.Digest([]byte("fixture"))}) == nil {
			t.Fatalf("unsafe input mode %o accepted", mode)
		}
	}
	authorityWrite(t, fs.root+"/etc/fixture.conf", nil, 0644)
	if err := checkPinnedInputFrom(fs, FilePin{Path: "/etc/fixture.conf", Digest: actionpermit.Digest(nil)}); err != nil {
		t.Fatal("empty reviewed config rejected", err)
	}
	f, err := os.OpenFile(fs.root+"/etc/fixture.conf", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxPinnedInputBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if checkPinnedInputFrom(fs, FilePin{Path: "/etc/fixture.conf", Digest: actionpermit.Digest(nil)}) == nil {
		t.Fatal("oversized input accepted")
	}
	for _, mutation := range []string{"symlink", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			fs, _, _ := authorityFixture(t)
			authorityWrite(t, fs.root+"/etc/fixture.conf", []byte("fixture"), 0644)
			if mutation == "symlink" {
				authoritySymlinkReplacement(t, fs.root+"/etc/fixture.conf")
			} else {
				mustAuthorityLink(t, fs.root+"/etc/fixture.conf", fs.root+"/input-link")
			}
			if checkPinnedInputFrom(fs, FilePin{Path: "/etc/fixture.conf", Digest: actionpermit.Digest([]byte("fixture"))}) == nil {
				t.Fatal("aliased input accepted")
			}
		})
	}
}

func authoritySocketFixture(t *testing.T) (authorityFS, *net.UnixListener, string) {
	t.Helper()
	// Unix path limits require a short directory independent of the test name.
	root, err := os.MkdirTemp("", "tb-action-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	fs := authorityFS{root: root, owner: uint32(os.Getuid())}
	if err := os.MkdirAll(filepath.Dir(root+SocketPath), 0700); err != nil {
		t.Fatal(err)
	}
	name := root + SocketPath
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("native Unix socket fixtures unavailable in this environment: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	t.Cleanup(func() { l.Close() })
	mustAuthorityChmod(t, name, 0660)
	return fs, l, name
}

func TestAuthorityKernelPeerCredentials(t *testing.T) {
	_, l, name := authoritySocketFixture(t)
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := l.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peer, err := peerIdentity(server)
	if err != nil || peer.UID != uint32(os.Getuid()) || peer.GID != uint32(os.Getgid()) || peer.PID != int32(os.Getpid()) {
		t.Fatal("kernel peer identity", peer, err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := peerIdentity(left); err == nil {
		t.Fatal("non-Unix peer accepted")
	}
	var absent *net.UnixConn
	if _, err := peerIdentity(absent); err == nil {
		t.Fatal("nil Unix peer accepted")
	}
	server.Close()
	if _, err := peerIdentity(server); err == nil {
		t.Fatal("closed Unix peer accepted")
	}
}

func TestAuthorityInheritedListenerFixture(t *testing.T) {
	fs, l, name := authoritySocketFixture(t)
	file, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	// The constructor borrows this duplicate and returns an independent listener.
	defer file.Close()
	env := map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "action-helper"}
	listener, err := inheritedListenerFrom(Policy{AgentGID: uint32(os.Getgid())}, fs, int(file.Fd()), name, func(k string) string { return env[k] }, os.Getpid())
	if err != nil {
		t.Fatal("valid inherited listener", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(name); err != nil {
		t.Fatal("listener close removed socket", err)
	}
}

func TestAuthorityInheritedListenerRejectsMismatch(t *testing.T) {
	for _, which := range []string{"pid", "fds", "fdnames", "name", "group", "mode", "symlink", "ancestor", "descriptor"} {
		t.Run(which, func(t *testing.T) {
			fs, l, name := authoritySocketFixture(t)
			file, err := l.File()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			env := map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "action-helper"}
			p := Policy{AgentGID: uint32(os.Getgid())}
			fd := int(file.Fd())
			switch which {
			case "pid":
				env["LISTEN_PID"] = "0" + env["LISTEN_PID"]
			case "fds":
				env["LISTEN_FDS"] = "2"
			case "fdnames":
				env["LISTEN_FDNAMES"] = "action-helper:other"
			case "name":
				name += ".wrong"
			case "group":
				p.AgentGID++
			case "mode":
				mustAuthorityChmod(t, name, 0666)
			case "symlink":
				authoritySymlinkReplacement(t, name)
			case "ancestor":
				mustAuthorityChmod(t, filepath.Dir(name), 0770)
			case "descriptor":
				fd = -1
			}
			got, err := inheritedListenerFrom(p, fs, fd, name, func(k string) string { return env[k] }, os.Getpid())
			if got != nil {
				got.Close()
			}
			if err == nil {
				t.Fatal("mismatched listener accepted")
			}
		})
	}
	fs, _, name := authoritySocketFixture(t)
	env := func(k string) string {
		return map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "action-helper"}[k]
	}
	// A stream socket is insufficient: it must already be listening.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if got, err := inheritedListenerFrom(Policy{AgentGID: uint32(os.Getgid())}, fs, fd, name, env, os.Getpid()); err == nil {
		got.Close()
		t.Fatal("unbound non-listening socket accepted")
	}
	udp, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(udp)
	if got, err := inheritedListenerFrom(Policy{AgentGID: uint32(os.Getgid())}, fs, udp, name, env, os.Getpid()); err == nil {
		got.Close()
		t.Fatal("datagram socket accepted")
	}
}

func TestAuthorityRejectsNonUnixPeerWithoutSocket(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := peerIdentity(left); err == nil {
		t.Fatal("non-Unix peer accepted")
	}
	if _, err := peerIdentity(nil); err == nil {
		t.Fatal("absent peer accepted")
	}
	var absent *net.UnixConn
	if _, err := peerIdentity(absent); err == nil {
		t.Fatal("nil Unix peer accepted")
	}
}

func TestAuthorityPathPrimitivesRejectTraversal(t *testing.T) {
	fs, _, _ := authorityFixture(t)
	for _, name := range []string{"", "relative", "/etc/../etc", "/etc//tracebolt", "/etc/tracebolt/", "/etc/trace\x00bolt", "/etc/trace bolt"} {
		if d, err := fs.openDirectories(name); err == nil {
			d.close()
			t.Fatalf("unsafe directory name %q accepted", name)
		}
	}
	d, err := fs.openDirectories("/etc/tracebolt")
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	for _, name := range []string{"", ".", "..", "../action-helper.json", "/action-helper.json", "nul\x00name"} {
		if f, err := d.readFile(name, MaxPolicyBytes, true); err == nil {
			f.close()
			t.Fatalf("unsafe filename %q accepted", name)
		}
	}
}

func TestAuthorityActivationRejectsWithoutSocket(t *testing.T) {
	fs := authorityFS{root: t.TempDir(), owner: uint32(os.Getuid())}
	for _, which := range []string{"empty", "pid", "fds", "fdnames", "descriptor"} {
		env := map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "action-helper"}
		switch which {
		case "empty":
			env = nil
		case "pid":
			env["LISTEN_PID"] = "0" + env["LISTEN_PID"]
		case "fds":
			env["LISTEN_FDS"] = "01"
		case "fdnames":
			env["LISTEN_FDNAMES"] = "action-helper:extra"
		}
		listener, err := inheritedListenerFrom(Policy{AgentGID: uint32(os.Getgid())}, fs, -1, "fixture", func(k string) string { return env[k] }, os.Getpid())
		if listener != nil {
			listener.Close()
		}
		if err == nil {
			t.Fatalf("invalid activation %q accepted", which)
		}
	}
}
