//go:build linux

package agentinstall

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
)

// ValidateOnlineBootstrapPreparation is a read-only gate BEFORE public network
// retrieval or temporary-file creation. Full installation ownership/state is
// checked again by Execute once the public bootstrap has been verified.
func ValidateOnlineBootstrapPreparation(ctx context.Context, r Request) error {
	if ctx == nil || ctx.Err() != nil || r.Action != Install || !r.Apply || r.BootstrapFile != "" || !validDigest(r.BootstrapSHA256) || !validDigest(r.AgentSHA256) || !validDigest(r.EnrollSHA256) || !validDigest(r.SourceSHA256) || !validInputPath(r.AgentBinary) || !validInputPath(r.EnrollBinary) || !validInputPath(r.SourceArchive) {
		return ErrContract
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || !actualSystemd() || !terminalReady() {
		return ErrPreflight
	}
	foreground, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	if err != nil || foreground != unix.Getpgrp() {
		return ErrPreflight
	}
	inputs, err := VerifyInputs(ctx, r)
	if err != nil {
		return ErrArtifact
	}
	inputs.Close()
	return nil
}
