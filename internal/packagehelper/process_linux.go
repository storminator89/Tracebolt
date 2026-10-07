//go:build linux

package packagehelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/mutationfence"
	"localrmm/internal/nativeapt"
	"os"
	"strconv"
	"strings"
)

type processRecord struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
	Mode  string `json:"mode"`
}

func parsePID(s string) (int, error) {
	n, e := strconv.Atoi(s)
	if e != nil || n < 0 || n > 1<<30 {
		return 0, ErrRejected
	}
	return n, nil
}
func procBytes(pid int, name string, max int) ([]byte, error) {
	if pid <= 0 {
		return nil, ErrRejected
	}
	f, e := os.Open(fmt.Sprintf("/proc/%d/%s", pid, name))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max {
		return nil, ErrRejected
	}
	return b, nil
}
func procIdentity(pid int) (int, string, error) {
	b, e := procBytes(pid, "stat", 8192)
	if e != nil {
		return 0, "", e
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 || end+2 >= len(b) {
		return 0, "", ErrRejected
	}
	fields := strings.Fields(string(b[end+2:]))
	if len(fields) < 20 {
		return 0, "", ErrRejected
	}
	ppid, e := parsePID(fields[1])
	if e != nil {
		return 0, "", e
	}
	if _, e = strconv.ParseUint(fields[19], 10, 64); e != nil {
		return 0, "", e
	}
	return ppid, fields[19], nil
}
func procRoot(pid int) error {
	b, e := procBytes(pid, "status", 64<<10)
	if e != nil {
		return e
	}
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") {
			f := strings.Fields(line)
			if len(f) != 5 {
				return ErrRejected
			}
			for _, v := range f[1:] {
				if v != "0" {
					return ErrRejected
				}
			}
			found++
		}
	}
	if found != 2 {
		return ErrRejected
	}
	return nil
}
func processExecutableDigest(pid int) (string, error) {
	if pid <= 0 {
		return "", ErrRejected
	}
	f, e := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if e != nil {
		return "", e
	}
	defer f.Close()
	var st, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || !safeFile(st, 0, 128<<20) {
		return "", ErrRejected
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 128<<20+1))
	if e != nil || n != st.Size || unix.Fstat(int(f.Fd()), &after) != nil || !sameFile(st, after) {
		return "", ErrRejected
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func (fs protectedFS) nativeLock(p string, acquire bool) (*os.File, int, error) {
	d, e := fs.dir("/var/lib/dpkg")
	if e != nil {
		return nil, 0, e
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), p, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, 0, e
	}
	f := os.NewFile(uintptr(fd), "dpkg-lock")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !safeFile(st, fs.owner, 4096) {
		f.Close()
		return nil, 0, ErrRejected
	}
	l := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	operation := unix.F_GETLK
	if acquire {
		operation = unix.F_SETLK
	}
	if e = unix.FcntlFlock(f.Fd(), operation, &l); e != nil {
		f.Close()
		return nil, 0, e
	}
	if acquire {
		return f, 0, nil
	}
	pid := int(l.Pid)
	if l.Type == unix.F_UNLCK {
		pid = 0
	}
	return f, pid, nil
}

// No environment token establishes custody. A proc-verified apt-get ancestor
// must match the recorded runner child, exact argv/env and frontend lock owner.
func proveAPTParent(fs protectedFS, a authority, id, mode string, inv nativeapt.Invocation) (processRecord, *os.File, error) {
	var expected processRecord
	if e := fs.json(jobFile(id, mode+".apt"), 4096, &expected); e != nil || expected.Mode != mode {
		return expected, nil, ErrRejected
	}
	pid := os.Getppid()
	seen := false
	for depth := 0; depth < 8 && pid > 1; depth++ {
		parent, start, e := procIdentity(pid)
		if e != nil {
			return expected, nil, e
		}
		if pid == expected.PID {
			if start != expected.Start || procRoot(pid) != nil {
				return expected, nil, ErrRejected
			}
			seen = true
			break
		}
		pid = parent
	}
	if !seen {
		return expected, nil, ErrRejected
	}
	pin := ""
	for _, p := range a.policy.Tools {
		if p.Path == nativeapt.APTExecutable {
			pin = p.Digest
		}
	}
	d, e := processExecutableDigest(expected.PID)
	if e != nil || d != pin {
		return expected, nil, ErrRejected
	}
	cmd, e := procBytes(expected.PID, "cmdline", 64<<10)
	wanted := append([]string{inv.Executable}, inv.Args...)
	if e != nil || !bytes.Equal(cmd, []byte(strings.Join(wanted, "\x00")+"\x00")) {
		return expected, nil, ErrRejected
	}
	env, e := procBytes(expected.PID, "environ", 64<<10)
	if e != nil || !bytes.Equal(env, []byte(strings.Join(inv.Env, "\x00")+"\x00")) {
		return expected, nil, ErrRejected
	}
	frontend, lockPID, e := fs.nativeLock("lock-frontend", false)
	if e != nil {
		return expected, nil, e
	}
	defer frontend.Close()
	if lockPID != expected.PID {
		return expected, nil, ErrRejected
	}
	inner, _, e := fs.nativeLock("lock", true)
	if e != nil {
		return expected, nil, e
	}
	_, start, e := procIdentity(expected.PID)
	if e != nil || start != expected.Start {
		inner.Close()
		return expected, nil, ErrRejected
	}
	return expected, inner, nil
}

// A matching executable alone is insufficient: this exact running helper must
// hold the current protected shared-fence inode throughout the observation.
func processHoldsMutationFence(fs protectedFS, pid int, start string) error {
	_, before, e := procIdentity(pid)
	if e != nil || before != start {
		return ErrRejected
	}
	file, st, e := fs.open(mutationfence.DefaultDirectory+"/fence.lock", mutationfence.MaxBytes)
	if e != nil {
		return ErrRejected
	}
	defer file.Close()
	directory, e := os.Open(fmt.Sprintf("/proc/%d/fd", pid))
	if e != nil {
		return ErrRejected
	}
	defer directory.Close()
	entries, e := directory.ReadDir(1025)
	if e != nil || len(entries) > 1024 {
		return ErrRejected
	}
	found := false
	for _, entry := range entries {
		if _, e := strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			return ErrRejected
		}
		var got unix.Stat_t
		if e = unix.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()), &got); e != nil {
			return ErrRejected
		}
		if got.Dev == st.Dev && got.Ino == st.Ino && sameFile(got, st) {
			found = true
		}
	}
	_, after, e := procIdentity(pid)
	if e != nil || after != start || !found {
		return ErrRejected
	}
	current, again, e := fs.open(mutationfence.DefaultDirectory+"/fence.lock", mutationfence.MaxBytes)
	if e != nil {
		return ErrRejected
	}
	current.Close()
	if !sameFile(st, again) {
		return ErrRejected
	}
	return nil
}
