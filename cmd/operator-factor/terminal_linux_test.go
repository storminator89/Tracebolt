//go:build linux

package main

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHiddenTerminalRestoresFlushesAndNeverEchoes(t *testing.T) {
	for _, mode := range []string{"success", "cancel", "ctrl-c", "eof", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			master, e := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(master)
			if unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0) != nil {
				t.Fatal("synthetic PTY unlock")
			}
			number, e := unix.IoctlGetInt(master, unix.TIOCGPTN)
			if e != nil {
				t.Fatal(e)
			}
			slave, e := unix.Open("/dev/pts/"+strconv.Itoa(number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(slave)
			original, e := unix.IoctlGetTermios(slave, unix.TCGETS)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { b, e := readTerminalFD(ctx, slave, "password"); done <- result{b, e} }()
			var transcript bytes.Buffer
			readAvailable := func() {
				var b [2048]byte
				n, err := unix.Read(master, b[:])
				if n > 0 {
					transcript.Write(b[:n])
				}
				if err != nil && err != unix.EAGAIN && err != unix.EINTR {
					t.Fatal("synthetic PTY output")
				}
			}
			for !strings.Contains(transcript.String(), "(hidden): ") {
				if ctx.Err() != nil {
					t.Fatal("synthetic prompt timeout")
				}
				poll := []unix.PollFd{{Fd: int32(master), Events: unix.POLLIN}}
				_, _ = unix.Poll(poll, 50)
				readAvailable()
			}
			hidden, e := unix.IoctlGetTermios(slave, unix.TCGETS)
			if e != nil || hidden.Lflag&(unix.ECHO|unix.ECHONL|unix.ISIG|unix.ICANON) != 0 {
				t.Fatal("input echo or signals not disabled")
			}
			payload := credentialCanary + "\n"
			switch mode {
			case "cancel":
				payload = credentialCanary
			case "ctrl-c":
				payload = credentialCanary + "\x03unread-canary"
			case "eof":
				payload = credentialCanary + "\x04unread-canary"
			case "overflow":
				payload = strings.Repeat("Z", 1025)
			}
			if n, e := unix.Write(master, []byte(payload)); e != nil || n != len(payload) {
				t.Fatal("synthetic input")
			}
			if mode == "cancel" {
				cancel()
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("terminal cancellation not bounded")
			}
			defer clear(got.data)
			if mode == "success" {
				if got.err != nil || string(got.data) != credentialCanary {
					t.Fatal("hidden input rejected")
				}
			} else if got.err == nil || len(got.data) != 0 {
				t.Fatal("failed prompt retained input")
			}
			restored, e := unix.IoctlGetTermios(slave, unix.TCGETS)
			if e != nil || !reflect.DeepEqual(restored, original) {
				t.Fatal("terminal settings not restored")
			}
			readAvailable()
			if strings.Contains(transcript.String(), credentialCanary) || strings.Contains(transcript.String(), "unread-canary") {
				t.Fatal("secret echo")
			}
			poll := []unix.PollFd{{Fd: int32(slave), Events: unix.POLLIN}}
			_, _ = unix.Poll(poll, 0)
			if poll[0].Revents&unix.POLLIN != 0 {
				t.Fatal("unread input survived restore")
			}
		})
	}
}
func TestHiddenTerminalRejectsNonTTY(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	if b, e := readTerminalFD(context.Background(), int(r.Fd()), "password"); e == nil || len(b) != 0 {
		clear(b)
		t.Fatal("redirected stdin accepted")
	}
}
