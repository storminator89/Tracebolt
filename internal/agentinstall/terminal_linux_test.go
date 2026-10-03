//go:build linux

package agentinstall

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// This exercises only a disposable PTY and inert copies of the Go test binary.
// No identity, account, installer apply, service or network operation is invoked.
func TestInstallerTerminalRestoresAfterKilledInertChild(t *testing.T) {
	mode := os.Getenv("TRACEBOLT_INERT_TTY_FIXTURE")
	if mode == "child" {
		signal.Ignore(syscall.SIGTERM)
		fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY, 0)
		if e != nil {
			os.Exit(10)
		}
		state, e := unix.IoctlGetTermios(fd, unix.TCGETS)
		if e != nil {
			os.Exit(11)
		}
		state.Lflag &^= unix.ECHO | unix.ICANON
		if unix.IoctlSetTermios(fd, unix.TCSETSF, state) != nil {
			os.Exit(12)
		}
		ready := os.NewFile(3, "inert-ready")
		ready.Write([]byte{1})
		ready.Close()
		time.Sleep(10 * time.Second)
		os.Exit(13)
	}
	if mode == "supervisor" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		read, write, e := os.Pipe()
		if e != nil {
			os.Exit(20)
		}
		executable, _ := os.Executable()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInstallerTerminalRestoresAfterKilledInertChild$")
		cmd.Env = []string{"TRACEBOLT_INERT_TTY_FIXTURE=child"}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = []*os.File{write}
		configureCancellation(cmd)
		cmd.WaitDelay = 100 * time.Millisecond
		ready := make(chan bool, 1)
		go func() { var b [1]byte; n, e := read.Read(b[:]); ready <- n == 1 && e == nil; cancel() }()
		e = runPreparedCommand(cmd, true)
		write.Close()
		read.Close()
		if e == nil || !<-ready {
			os.Exit(21)
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fd, e := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal("disposable PTY")
	}
	master := os.NewFile(uintptr(fd), "inert-master")
	defer master.Close()
	if unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0) != nil {
		t.Fatal("PTY unlock")
	}
	n, e := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if e != nil {
		t.Fatal("PTY number")
	}
	slave, e := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR, 0)
	if e != nil {
		t.Fatal("PTY slave")
	}
	defer slave.Close()
	original, e := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if e != nil {
		t.Fatal("termios")
	}
	executable, _ := os.Executable()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInstallerTerminalRestoresAfterKilledInertChild$")
	cmd.Env = []string{"TRACEBOLT_INERT_TTY_FIXTURE=supervisor"}
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if cmd.Run() != nil {
		t.Fatal("inert terminal cancellation failed")
	}
	restored, e := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if e != nil || *restored != *original {
		t.Fatal("parent failed to restore killed child's terminal")
	}
}
