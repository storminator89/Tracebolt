//go:build linux

package packagehelper

import (
	"bytes"
	"context"
	"io"
	"localrmm/internal/nativeapt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type commandSpec struct {
	executable string
	args, env  []string
	timeout    time.Duration
	started    func(int) error
}
type commandResult struct {
	exit    int
	stdout  []byte
	started bool
}
type commands interface {
	run(commandSpec) (commandResult, error)
}
type limitedOutput struct {
	bytes.Buffer
	max int
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

type realCommands struct{}

func (realCommands) run(s commandSpec) (commandResult, error) {
	var ctx context.Context
	var cancel context.CancelFunc
	var cmd *exec.Cmd
	// Only preparation/capture/read-only service checks receive cancellation.
	// Applying apt-get intentionally uses exec.Command, never CommandContext.
	if s.timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, s.executable, s.args...)
	} else {
		cmd = exec.Command(s.executable, s.args...)
	}
	cmd.Env = s.env
	cmd.Dir = "/"
	cmd.Stdin = nil
	out := &limitedOutput{max: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if e := cmd.Start(); e != nil {
		return commandResult{exit: -1}, e
	}
	r := commandResult{started: true, exit: -1}
	if s.started != nil {
		if e := s.started(cmd.Process.Pid); e != nil {
			// Never kill an applying process after an uncertain write. It cannot pass the
			// guard without its durable apt identity; wait and retain uncertainty.
			_ = cmd.Wait()
			return r, e
		}
	}
	e := cmd.Wait()
	r.stdout = bytes.Clone(out.Bytes())
	if cmd.ProcessState != nil {
		r.exit = cmd.ProcessState.ExitCode()
	}
	return r, e
}
func fixedEnv() []string { return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"} }
func checkServiceQuiescent(ctx context.Context, c commands) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	for _, unit := range []string{"tracebolt-action-helper.service", "tracebolt-action-helper.socket"} {
		r, e := c.run(commandSpec{SystemctlExecutable, []string{"show", "--property=ActiveState", "--value", unit}, fixedEnv(), 10 * time.Second, nil})
		if e != nil || r.exit != 0 || string(r.stdout) != "inactive\n" {
			return ErrRejected
		}
	}
	return nil
}
func startRunner(c commands, id string) error {
	if _, e := nativeapt.JobPaths(id); e != nil {
		return e
	}
	if !runnerDefinition(c, id) {
		return ErrRejected
	}
	_, e := c.run(commandSpec{SystemctlExecutable, []string{"--no-ask-password", "--no-block", "start", "tracebolt-package-runner@" + id + ".service"}, fixedEnv(), 10 * time.Second, nil})
	return e
}

// A live previous-generation helper cannot coexist just because its executable
// was replaced on disk. Require its running /proc image to match the reviewed
// current pinned helper, or require service inactivity.
func checkServiceGeneration(c commands, a authority) error {
	r, e := c.run(commandSpec{SystemctlExecutable, []string{"show", "--property=MainPID", "--value", "tracebolt-action-helper.service"}, fixedEnv(), 10 * time.Second, nil})
	if e != nil || r.exit != 0 {
		return ErrRejected
	}
	pid, e := parsePID(strings.TrimSpace(string(r.stdout)))
	if e != nil {
		return e
	}
	if pid == 0 {
		return nil
	}
	_, start, e := procIdentity(pid)
	if e != nil {
		return ErrRejected
	}
	d, e := processExecutableDigest(pid)
	if e != nil || d != a.policy.Tools[0].Digest || processHoldsMutationFence(hostFS(), pid, start) != nil {
		return ErrRejected
	}
	return nil
}

var _ = os.ErrNotExist

func runnerInactive(c commands, id string) error {
	if _, e := nativeapt.JobPaths(id); e != nil {
		return e
	}
	r, e := c.run(commandSpec{SystemctlExecutable, []string{"show", "--property=ActiveState", "--value", "tracebolt-package-runner@" + id + ".service"}, fixedEnv(), 10 * time.Second, nil})
	if e != nil || r.exit != 0 || string(r.stdout) != "inactive\n" {
		return ErrUnavailable
	}
	return nil
}

func unitStopped(c commands, id string) bool {
	if _, e := nativeapt.JobPaths(id); e != nil {
		return false
	}
	r, e := c.run(commandSpec{SystemctlExecutable, []string{"show", "--property=ActiveState", "--property=Job", "--property=MainPID", "tracebolt-package-runner@" + id + ".service"}, fixedEnv(), 10 * time.Second, nil})
	if e != nil || r.exit != 0 {
		return false
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(r.stdout), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, seen := values[k]; seen {
			return false
		}
		if k != "ActiveState" && k != "Job" && k != "MainPID" {
			return false
		}
		values[k] = v
	}
	if len(values) != 3 {
		return false
	}
	return (values["ActiveState"] == "inactive" || values["ActiveState"] == "failed") && values["MainPID"] == "0" && (values["Job"] == "" || values["Job"] == "0")
}

func runnerDefinition(c commands, id string) bool {
	r, e := c.run(commandSpec{SystemctlExecutable, []string{"show", "--property=FragmentPath", "--property=DropInPaths", "--property=NeedDaemonReload", "--property=Slice", "tracebolt-package-runner@" + id + ".service"}, fixedEnv(), 10 * time.Second, nil})
	if e != nil || r.exit != 0 {
		return false
	}
	want := map[string]string{"FragmentPath": RunnerUnitPath, "DropInPaths": "", "NeedDaemonReload": "no", "Slice": "system.slice"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(r.stdout), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		expected, exists := want[k]
		if !ok || !exists || seen[k] || v != expected {
			return false
		}
		seen[k] = true
	}
	return len(seen) == len(want)
}
