//go:build darwin

package macosinventory

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// No shell, caller-supplied arguments, inherited environment, stdin, arbitrary
// paths, root helper or persistent files. Output overflow cancels the command;
// every started child is waited/reaped. Stderr is counted but never retained.
func runFixedCommand(parent context.Context, which fixedCommand) ([]byte, error) {
	spec, e := specification(which)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(parent, CommandBudget)
	defer cancel()
	out := newOutputBudget(spec.maxBytes, cancel)
	cmd := exec.CommandContext(ctx, spec.path, spec.args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdout = out.stdout()
	cmd.Stderr = out.stderr()
	cmd.WaitDelay = 200 * time.Millisecond
	e = cmd.Run()
	if out.exceeded() {
		return nil, ErrBounds
	}
	if ctx.Err() != nil {
		return nil, ErrBudget
	}
	if e != nil {
		if errors.Is(e, exec.ErrWaitDelay) {
			return nil, ErrBudget
		}
		return nil, safeError(e)
	}
	if out.hasStderr() {
		return nil, ErrUnavailable
	}
	return out.bytes(), nil
}
