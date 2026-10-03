//go:build linux

package agentinstall

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type cappedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 4096 {
		w.exceeded = true
		return 0, ErrOperation
	}
	return w.Buffer.Write(p)
}
func runFixedCommand(ctx context.Context, path string, args []string, account *accountRecord, interactive bool) (result error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return ErrPreflight
	}
	// The unexported caller supplies only fixed, reviewed executables and argv.
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrContract
	}
	cmdArgs := append([]string(nil), args...)
	verify := ""
	if path == systemctlPath && len(args) == 2 && (args[0] == "verify-stopped" || args[0] == "verify-active") {
		verify = args[0]
		cmdArgs = []string{"show", UnitName, "--property=ActiveState,MainPID,ControlPID,ControlGroup", "--no-pager"}
	}
	cmd := exec.CommandContext(ctx, path, cmdArgs...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	configureCancellation(cmd)
	var output cappedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if account != nil {
		if !validAccountID(account.UID) || !validAccountID(account.GID) {
			return ErrPreflight
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(account.UID), Gid: uint32(account.GID), Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
		cmd.Env = append(cmd.Env, "USER="+Account, "LOGNAME="+Account)
	}
	if interactive {
		if account == nil {
			return ErrPreflight
		}
		// Inherit the existing terminal only. No TTY ownership/chmod, alternate root
		// prompt, token argument/environment, or privilege-retaining fallback.
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if runPreparedCommand(cmd, interactive) != nil || output.exceeded {
		return ErrOperation
	}
	if verify != "" {
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				return ErrOperation
			}
			if _, duplicate := values[kv[0]]; duplicate {
				return ErrOperation
			}
			values[kv[0]] = kv[1]
		}
		if len(values) != 4 || values["MainPID"] == "" || values["ControlPID"] != "0" {
			return ErrOperation
		}
		if _, e := strconv.ParseUint(values["MainPID"], 10, 32); e != nil {
			return ErrOperation
		}
		if verify == "verify-stopped" && !stoppedCgroup(values["ControlGroup"]) {
			return ErrOperation
		}
		if verify == "verify-stopped" && (values["MainPID"] != "0" || (values["ActiveState"] != "inactive" && values["ActiveState"] != "failed")) {
			return ErrOperation
		}
		if verify == "verify-active" && (values["ActiveState"] != "active" || values["MainPID"] == "0") {
			return ErrOperation
		}
	}
	return nil
}

func terminalReady() bool {
	if _, e := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); e != nil {
		return false
	}
	i, e := os.Lstat("/dev/tty")
	if e != nil || i.Mode()&os.ModeCharDevice == 0 || i.Mode().Perm()&0006 != 0006 {
		return false
	}
	fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return false
	}
	defer unix.Close(fd)
	_, e = unix.IoctlGetTermios(fd, unix.TCGETS)
	return e == nil
}
func stoppedCgroup(group string) bool {
	const expected = "/system.slice/tracebolt-agent.service"
	if group != "" && group != expected {
		return false
	}
	raw, e := os.ReadFile("/sys/fs/cgroup" + expected + "/cgroup.events")
	if os.IsNotExist(e) {
		return true
	}
	if e != nil || len(raw) > 4096 {
		return false
	}
	return cgroupUnpopulated(raw)
}
func cgroupUnpopulated(raw []byte) bool {
	seen := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return false
		}
		if parts[0] == "populated" {
			if seen || parts[1] != "0" {
				return false
			}
			seen = true
		}
	}
	return seen
}

func preserveTerminal() (func() error, error) {
	if !terminalReady() {
		return nil, ErrPreflight
	}
	fd, e := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrPreflight
	}
	before, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		unix.Close(fd)
		return nil, ErrPreflight
	}
	return func() error {
		e := unix.IoctlSetTermios(fd, unix.TCSETSF, before)
		ce := unix.Close(fd)
		if e != nil || ce != nil {
			return ErrOperation
		}
		return nil
	}, nil
}

func configureCancellation(cmd *exec.Cmd) {
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
}

// Tests call this unexported process/TTY seam only with disposable test children.
// The production caller has already bound argv, environment and numeric IDs.
func runPreparedCommand(cmd *exec.Cmd, interactive bool) (result error) {
	if interactive {
		restore, e := preserveTerminal()
		if e != nil {
			return ErrPreflight
		}
		defer func() {
			if restore() != nil {
				result = ErrOperation
			}
		}()
	}
	if cmd.Run() != nil {
		return ErrOperation
	}
	return nil
}
