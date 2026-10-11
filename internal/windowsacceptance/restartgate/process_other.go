//go:build !windows

package restartgate

import "os/exec"

func isolateCommand(cmd *exec.Cmd) error { cmd.Env = []string{}; return nil }
