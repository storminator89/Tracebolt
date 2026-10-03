//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHiddenTerminalPromptSyntheticFixture(t *testing.T) {
	if os.Getenv("TRACEBOLT_SYNTHETIC_TERMINAL_TEST") == "1" {
		secret, e := readInvitation(context.Background(), func() error {
			fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY, 0)
			if e != nil {
				return e
			}
			defer unix.Close(fd)
			state, e := unix.IoctlGetTermios(fd, unix.TCGETS)
			if e != nil || state.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
				return fmt.Errorf("echo was enabled before prompt")
			}
			_, e = fmt.Fprint(os.Stdout, "SYNTHETIC_HIDDEN_PROMPT:")
			return e
		})
		if e != nil || len(secret) != 43 {
			clear(secret)
			os.Exit(3)
		}
		clear(secret)
		fmt.Fprint(os.Stdout, "SYNTHETIC_READ_OK")
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	masterFD, e := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	master := os.NewFile(uintptr(masterFD), "synthetic-pty-master")
	defer master.Close()
	if e = unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); e != nil {
		t.Fatal(e)
	}
	number, e := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if e != nil {
		t.Fatal(e)
	}
	slave, e := os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer slave.Close()
	original, e := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHiddenTerminalPromptSyntheticFixture$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_SYNTHETIC_TERMINAL_TEST=1")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	output := make(chan string, 1)
	readError := make(chan error, 1)
	go func() {
		var b bytes.Buffer
		one := make([]byte, 1)
		for {
			n, e := master.Read(one)
			if n > 0 {
				b.Write(one[:n])
				if strings.Contains(b.String(), "SYNTHETIC_HIDDEN_PROMPT:") {
					output <- b.String()
					return
				}
			}
			if e != nil {
				readError <- e
				return
			}
		}
	}()
	var transcript string
	select {
	case transcript = <-output:
	case e := <-readError:
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal(e)
	case <-ctx.Done():
		cmd.Wait()
		t.Fatal("synthetic prompt timed out")
	}
	// Deliberately write immediately on seeing the prompt, without a sleep.
	secret := strings.Repeat("A", 43)
	if _, e = io.WriteString(master, secret+"\n"); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Wait(); e != nil {
		t.Fatal("synthetic terminal child failed", e)
	}
	restored, e := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if e != nil || *restored != *original {
		t.Fatal("terminal settings were not restored")
	}
	slave.Close()
	rest, _ := io.ReadAll(master)
	transcript += string(rest)
	if strings.Contains(transcript, secret) || !strings.Contains(transcript, "SYNTHETIC_READ_OK") {
		t.Fatal("hidden terminal fixture did not preserve secrecy")
	}
}
