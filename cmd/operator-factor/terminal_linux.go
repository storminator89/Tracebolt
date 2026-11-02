//go:build linux

package main

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
	"unicode/utf8"
)

const platformSupported = true

func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
func promptText(kind string) string {
	switch kind {
	case "username":
		return "Operator username (hidden): "
	case "password":
		return "Operator password (hidden): "
	case "login_otp":
		return "Current authenticator code (blank only if no factor; hidden): "
	case "enrollment_otp":
		return "New authenticator code proving possession (hidden): "
	case "fresh_password":
		return "Re-enter REQUESTER password for factor reset (hidden): "
	case "fresh_otp":
		return "Wait for a NEW unused authenticator code, then enter it (hidden): "
	}
	return ""
}
func readTerminal(ctx context.Context, kind string) ([]byte, error) {
	fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, errInput
	}
	defer unix.Close(fd)
	foreground, e := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if e != nil || foreground != unix.Getpgrp() {
		return nil, errInput
	}
	return readTerminalFD(ctx, fd, kind)
}

// Package-private descriptor seam, used only with synthetic PTYs in tests.
func readTerminalFD(ctx context.Context, fd int, kind string) (value []byte, err error) {
	label := promptText(kind)
	if label == "" || ctx.Err() != nil {
		return nil, errInput
	}
	original, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return nil, errInput
	}
	hidden := *original
	hidden.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	hidden.Iflag &^= unix.IXON | unix.IXOFF | unix.ISTRIP | unix.IUCLC | unix.INLCR | unix.IGNCR | unix.ICRNL
	hidden.Cc[unix.VMIN], hidden.Cc[unix.VTIME] = 0, 0
	if unix.IoctlSetTermios(fd, unix.TCSETSF, &hidden) != nil {
		return nil, errInput
	}
	defer func() {
		if unix.IoctlSetTermios(fd, unix.TCSETSF, original) != nil {
			clear(value)
			value = nil
			err = errInput
		}
		_, _ = unix.Write(fd, []byte("\n"))
	}()
	if n, e := unix.Write(fd, []byte(label)); e != nil || n != len(label) {
		return nil, errInput
	}
	maximum := 8
	if kind == "username" {
		maximum = 64
	}
	if kind == "password" || kind == "fresh_password" {
		maximum = 1024
	}
	secret := make([]byte, 0, maximum)
	keep := false
	defer func() {
		if !keep {
			clear(secret)
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil, errInput
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, e := unix.Poll(poll, 100)
		if e == unix.EINTR {
			continue
		}
		if e != nil || poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, errInput
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var one [1]byte
		n, e := unix.Read(fd, one[:])
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil || n != 1 {
			return nil, errInput
		}
		c := one[0]
		clear(one[:])
		if c == '\r' || c == '\n' {
			if !validInput(kind, secret) {
				return nil, errInput
			}
			keep = true
			return secret, nil
		}
		if c == 3 || c == 4 || c == 26 {
			return nil, errInput
		}
		if c == 127 || c == 8 {
			if len(secret) > 0 {
				_, n := utf8.DecodeLastRune(secret)
				clear(secret[len(secret)-n:])
				secret = secret[:len(secret)-n]
			}
			continue
		}
		if len(secret) >= maximum || c < 32 {
			return nil, errInput
		}
		secret = append(secret, c)
	}
}
