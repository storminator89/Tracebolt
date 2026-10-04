//go:build linux

package main

import (
	"context"
	"golang.org/x/sys/unix"
	"localrmm/internal/enrollmentclient"
	"os"
)

// readInvitation uses a controlling terminal only. Reads are bounded, echo is
// disabled, cancellation is polled, and terminal settings are always restored.
func readInvitation(ctx context.Context, prompt func() error) ([]byte, error) {
	fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, enrollmentclient.ErrInput
	}
	f := os.NewFile(uintptr(fd), "enrollment-terminal")
	defer f.Close()
	original, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return nil, enrollmentclient.ErrInput
	}
	hidden := *original
	hidden.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON
	hidden.Cc[unix.VMIN] = 0
	hidden.Cc[unix.VTIME] = 0
	if unix.IoctlSetTermios(fd, unix.TCSETSF, &hidden) != nil {
		return nil, enrollmentclient.ErrInput
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETSF, original) }()
	if prompt == nil || prompt() != nil {
		return nil, enrollmentclient.ErrInput
	}
	secret := make([]byte, 0, 43)
	success := false
	// Recognize only standard bracketed-paste delimiters. They frame input;
	// they are never part of the invitation and do not submit it.
	var delimiter string
	delimiterAt := 0
	pasting, pasted := false, false
	defer func() {
		if !success {
			clear(secret)
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, e = unix.Poll(p, 100)
		if e == unix.EINTR {
			continue
		}
		if e != nil || p[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, enrollmentclient.ErrInput
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
			return nil, enrollmentclient.ErrInput
		}
		c := one[0]
		if delimiterAt != 0 {
			if c != delimiter[delimiterAt] {
				return nil, enrollmentclient.ErrInput
			}
			delimiterAt++
			if delimiterAt == len(delimiter) {
				delimiterAt = 0
				if pasting {
					if len(secret) != 43 {
						return nil, enrollmentclient.ErrInput
					}
					pasting, pasted = false, true
				} else {
					pasting = true
				}
			}
			continue
		}
		if c == 27 {
			switch {
			case pasting:
				delimiter = "\x1b[201~"
			case len(secret) == 0 && !pasted:
				delimiter = "\x1b[200~"
			default:
				return nil, enrollmentclient.ErrInput
			}
			delimiterAt = 1
			continue
		}
		if pasting && (c == '\n' || c == '\r' || c == 127 || c == 8) {
			return nil, enrollmentclient.ErrInput
		}
		if pasted && c != '\n' && c != '\r' {
			return nil, enrollmentclient.ErrInput
		}
		if c == '\n' || c == '\r' {
			if len(secret) != 43 {
				return nil, enrollmentclient.ErrInput
			}
			success = true
			return secret, nil
		}
		if c == 127 || c == 8 {
			if len(secret) > 0 {
				secret[len(secret)-1] = 0
				secret = secret[:len(secret)-1]
			}
			continue
		}
		if len(secret) >= 43 || !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, enrollmentclient.ErrInput
		}
		secret = append(secret, c)
	}
}
