//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/enrollmentclient"
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
		ctx := context.Background()
		if os.Getenv("TRACEBOLT_SYNTHETIC_TERMINAL_RESULT") == "cancel" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()
		}
		secret, e := readInvitation(ctx, func() error {
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
		valid := false
		switch os.Getenv("TRACEBOLT_SYNTHETIC_TERMINAL_RESULT") {
		case "valid":
			valid = e == nil && string(secret) == strings.Repeat("A", 43)
		case "reject":
			valid = errors.Is(e, enrollmentclient.ErrInput) && len(secret) == 0
		case "cancel":
			valid = errors.Is(e, context.DeadlineExceeded) && len(secret) == 0
		}
		if !valid {
			clear(secret)
			os.Exit(3)
		}
		clear(secret)
		fmt.Fprint(os.Stdout, "SYNTHETIC_READ_OK")
		os.Exit(0)
	}
	runSyntheticInvitationPTY(t, strings.Repeat("A", 43)+"\n", "valid")
}

func TestHiddenTerminalBracketedPasteSyntheticFixtures(t *testing.T) {
	key := strings.Repeat("A", 43)
	for _, tc := range []struct{ name, input, expected string }{
		{"paste_then_enter", "\x1b[200~" + key + "\x1b[201~\n", "valid"},
		{"paste_then_carriage_return", "\x1b[200~" + key + "\x1b[201~\r", "valid"},
		{"plain_backspace", "B\x7f" + key + "\n", "valid"},
		{"short_plain", key[:42] + "\n", "reject"},
		{"long_plain", key + "A\n", "reject"},
		{"space_plain", " " + key + "\n", "reject"},
		{"unknown_escape", "\x1b[31m" + key + "\n", "reject"},
		{"unexpected_end", "\x1b[201~" + key + "\n", "reject"},
		{"typed_prefix", "A\x1b[200~" + key + "\x1b[201~\n", "reject"},
		{"empty_paste", "\x1b[200~\x1b[201~\n", "reject"},
		{"short_paste", "\x1b[200~" + key[:42] + "\x1b[201~\n", "reject"},
		{"long_paste", "\x1b[200~" + key + "A\x1b[201~\n", "reject"},
		{"multiline_paste", "\x1b[200~" + key + "\n\x1b[201~\n", "reject"},
		{"editing_inside_paste", "\x1b[200~A\x7f" + key + "\x1b[201~\n", "reject"},
		{"nested_paste", "\x1b[200~\x1b[200~" + key + "\x1b[201~\n", "reject"},
		{"second_paste", "\x1b[200~" + key + "\x1b[201~\x1b[200~\n", "reject"},
		{"suffix_after_paste", "\x1b[200~" + key + "\x1b[201~A\n", "reject"},
		{"incomplete_start_cancel", "\x1b[20", "cancel"},
		{"incomplete_end_cancel", "\x1b[200~" + key + "\x1b[20", "cancel"},
		{"complete_paste_waits_for_enter", "\x1b[200~" + key + "\x1b[201~", "cancel"},
	} {
		t.Run(tc.name, func(t *testing.T) { runSyntheticInvitationPTY(t, tc.input, tc.expected) })
	}
}

func runSyntheticInvitationPTY(t *testing.T, input, expected string) {
	t.Helper()
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
	cmd.Env = append(os.Environ(), "TRACEBOLT_SYNTHETIC_TERMINAL_TEST=1", "TRACEBOLT_SYNTHETIC_TERMINAL_RESULT="+expected)
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
	if _, e = io.WriteString(master, input); e != nil {
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
	if strings.Contains(transcript, secret[:8]) || strings.Contains(transcript, "[200~") || strings.Contains(transcript, "[201~") || !strings.Contains(transcript, "SYNTHETIC_READ_OK") {
		t.Fatal("hidden terminal fixture did not preserve secrecy")
	}
}
