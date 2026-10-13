//go:build darwin

package agentidentity

import (
	"golang.org/x/sys/unix"
	"os"
)

// Darwin has no getresuid/getresgid. The self-only kernel snapshot exposes
// real and saved IDs; getuid/geteuid/getgid/getegid independently bind it to
// this running process. Failure never substitutes effective-only admission.
func serviceProcessIDs(uid, gid int) bool {
	if unix.Getuid() != uid || unix.Geteuid() != uid || unix.Getgid() != gid || unix.Getegid() != gid {
		return false
	}
	p, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil || p == nil || p.Proc.P_pid != int32(os.Getpid()) {
		return false
	}
	return darwinIDsMatch(p, uint32(uid), uint32(gid))
}
func darwinIDsMatch(p *unix.KinfoProc, uid, gid uint32) bool {
	if p == nil || p.Eproc.Pcred.P_ruid != uid || p.Eproc.Pcred.P_svuid != uid || p.Eproc.Pcred.P_rgid != gid || p.Eproc.Pcred.P_svgid != gid || p.Eproc.Ucred.Uid != uid || p.Eproc.Ucred.Ngroups < 1 || int(p.Eproc.Ucred.Ngroups) > len(p.Eproc.Ucred.Groups) {
		return false
	}
	for _, group := range p.Eproc.Ucred.Groups[:p.Eproc.Ucred.Ngroups] {
		if group != gid {
			return false
		}
	}
	return true
}
