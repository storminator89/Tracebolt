//go:build darwin

package macosservice

import (
	"context"
	"os/exec"
	"time"
)

// Native account reads are fixed, local, inherited-unprivileged and bounded.
// No shell, service operation, credential input or caller-supplied command exists.
func readLocalAccount(ctx context.Context, args []string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !validAccountQuery(args) {
		return nil, ErrPreflight
	}
	run, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(run, "/usr/bin/dscl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 200 * time.Millisecond
	out := &boundedAccountOutput{limit: maxAccountOutput}
	errOut := &boundedAccountOutput{limit: 512}
	cmd.Stdout = out
	cmd.Stderr = errOut
	if cmd.Run() != nil || run.Err() != nil || out.exceeded || errOut.exceeded {
		return nil, ErrPreflight
	}
	return out.buffer.Bytes(), nil
}
