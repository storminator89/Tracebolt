//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func platformSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP}
}

func closeParent(fd int) { _ = unix.Close(fd) }
func protectedDirectory(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Gid == 0 && st.Mode&0022 == 0
}
func openProtectedParent() (int, error) {
	root, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, errSetup
	}
	defer unix.Close(root)
	if !protectedDirectory(root) {
		return -1, errSetup
	}
	parent, e := unix.Openat(root, "etc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, errSetup
	}
	if !protectedDirectory(parent) {
		unix.Close(parent)
		return -1, errSetup
	}
	return parent, nil
}
func outputAbsent(parent int) error {
	var st unix.Stat_t
	if e := unix.Fstatat(parent, outputName, &st, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		return errSetup
	}
	// Leftover staging output is ambiguous after a crash. Never adopt or reset it.
	dup, e := unix.Openat(parent, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return errSetup
	}
	f := os.NewFile(uintptr(dup), "setup-parent")
	names, e := f.Readdirnames(-1)
	f.Close()
	if e != nil {
		return errSetup
	}
	for _, name := range names {
		if len(name) >= len(stagePrefix) && name[:len(stagePrefix)] == stagePrefix {
			return errSetup
		}
	}
	return nil
}

const stagePrefix = ".tracebolt-http-test-setup-"

type publicationOps struct {
	sync    func(int) error
	handoff func(int, int, int) error
}

func publish(ctx context.Context, parent int, files []materialFile, uid, gid int) error {
	return publishWithOps(ctx, parent, files, uid, gid, publicationOps{sync: unix.Fsync, handoff: unix.Fchown})
}

// The operation seam exists only for synthetic failure testing, never CLI input.
func publishWithOps(ctx context.Context, parent int, files []materialFile, uid, gid int, ops publicationOps) error {
	if len(files) != len(fileNames) || outputAbsent(parent) != nil {
		return errSetup
	}
	for i, f := range files {
		if f.name != fileNames[i] || len(f.data) == 0 {
			return errSetup
		}
	}
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil {
		return errSetup
	}
	name := stagePrefix + hex.EncodeToString(random[:])
	if e := unix.Mkdirat(parent, name, 0700); e != nil {
		return errSetup
	}
	stage, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		return errSetup
	}
	defer unix.Close(stage)
	published := false
	defer func() {
		if !published {
			for _, f := range files {
				_ = unix.Unlinkat(stage, f.name, 0)
			}
			_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		}
	}()
	// Set only this newly created directory, including under a restrictive umask.
	if unix.Fchmod(stage, 0700) != nil {
		return errSetup
	}
	for _, f := range files {
		if ctx.Err() != nil {
			return errSetup
		}
		fd, e := unix.Openat(stage, f.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return errSetup
		}
		file := os.NewFile(uintptr(fd), "setup-private-file")
		e = file.Chmod(0600)
		if e == nil {
			_, e = file.Write(f.data)
		}
		if e == nil {
			e = file.Chown(uid, gid)
		}
		if e == nil {
			e = file.Sync()
		}
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return errSetup
		}
	}
	if ops.sync(stage) != nil || ctx.Err() != nil {
		return errSetup
	}
	// Linux no-replace rename publishes the complete new directory atomically.
	if unix.Renameat2(parent, name, parent, outputName, unix.RENAME_NOREPLACE) != nil {
		return errSetup
	}
	published = true // Every later failure preserves output for manual inspection.
	if ops.sync(parent) != nil {
		return errSetup
	}
	// Final mutation: hand off the pinned directory only after publication.
	// Never perform privileged path writes or cleanup after runtime ownership.
	if ops.handoff(stage, uid, gid) != nil || ops.sync(stage) != nil {
		return errSetup
	}
	return nil
}

func readPassword(ctx context.Context) ([]byte, error) {
	fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, errSetup
	}
	defer unix.Close(fd)
	foreground, e := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if e != nil || foreground != unix.Getpgrp() {
		return nil, errSetup
	}
	return readPasswordFD(ctx, fd)
}

// The fd seam is used only by synthetic tests. Production opens /dev/tty itself.
func readPasswordFD(ctx context.Context, fd int) (password []byte, err error) {
	original, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return nil, errSetup
	}
	hidden := *original
	hidden.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	hidden.Iflag &^= unix.IXON | unix.IXOFF | unix.ISTRIP | unix.IUCLC | unix.INLCR | unix.IGNCR | unix.ICRNL
	hidden.Cc[unix.VMIN], hidden.Cc[unix.VTIME] = 0, 0
	if unix.IoctlSetTermios(fd, unix.TCSETSF, &hidden) != nil {
		return nil, errSetup
	}
	defer func() {
		// Flush unread password bytes and restore even after cancellation/failure.
		if unix.IoctlSetTermios(fd, unix.TCSETSF, original) != nil {
			clear(password)
			password = nil
			err = errSetup
		}
		_, _ = unix.Write(fd, []byte("\n"))
	}()
	write := func(s string) error {
		n, e := unix.Write(fd, []byte(s))
		if e != nil || n != len(s) {
			return errSetup
		}
		return nil
	}
	if write("Disposable HTTP-test password (12–1024 UTF-8 bytes): ") != nil {
		return nil, errSetup
	}
	first, e := readHiddenLine(ctx, fd)
	if e != nil {
		return nil, errSetup
	}
	keep := false
	defer func() {
		if !keep {
			clear(first)
		}
	}()
	if !validPassword(first) {
		return nil, errSetup
	}
	if write("\nConfirm password: ") != nil {
		return nil, errSetup
	}
	second, e := readHiddenLine(ctx, fd)
	defer clear(second)
	if e != nil || subtle.ConstantTimeCompare(first, second) != 1 {
		return nil, errSetup
	}
	keep = true
	return first, nil
}
func readHiddenLine(ctx context.Context, fd int) ([]byte, error) {
	secret := make([]byte, 0, 1024)
	keep := false
	defer func() {
		if !keep {
			clear(secret)
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil, errSetup
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, e := unix.Poll(p, 100)
		if e == unix.EINTR {
			continue
		}
		if e != nil || p[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, errSetup
		}
		if p[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var one [1]byte
		n, e := unix.Read(fd, one[:])
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil || n != 1 {
			return nil, errSetup
		}
		c := one[0]
		if c == '\n' || c == '\r' {
			keep = true
			return secret, nil
		}
		if c == 3 || c == 4 || c == 26 {
			return nil, errSetup
		}
		if c == 127 || c == 8 {
			if len(secret) > 0 {
				_, n := utf8.DecodeLastRune(secret)
				clear(secret[len(secret)-n:])
				secret = secret[:len(secret)-n]
			}
			continue
		}
		if len(secret) >= 1024 || c < 32 {
			return nil, errSetup
		}
		secret = append(secret, c)
	}
}
