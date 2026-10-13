//go:build darwin

package agentidentity

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestDarwinIDsRequireRealSavedEffectiveAndBoundedGroups(t *testing.T) {
	p := unix.KinfoProc{}
	p.Eproc.Pcred.P_ruid = 501
	p.Eproc.Pcred.P_svuid = 501
	p.Eproc.Pcred.P_rgid = 501
	p.Eproc.Pcred.P_svgid = 501
	p.Eproc.Ucred.Uid = 501
	p.Eproc.Ucred.Ngroups = 1
	p.Eproc.Ucred.Groups[0] = 501
	if !darwinIDsMatch(&p, 501, 501) {
		t.Fatal("exact identity rejected")
	}
	for _, change := range []func(*unix.KinfoProc){
		func(p *unix.KinfoProc) { p.Eproc.Pcred.P_ruid = 0 }, func(p *unix.KinfoProc) { p.Eproc.Pcred.P_svuid = 0 }, func(p *unix.KinfoProc) { p.Eproc.Pcred.P_rgid = 0 }, func(p *unix.KinfoProc) { p.Eproc.Pcred.P_svgid = 0 }, func(p *unix.KinfoProc) { p.Eproc.Ucred.Uid = 0 }, func(p *unix.KinfoProc) { p.Eproc.Ucred.Ngroups = 0 }, func(p *unix.KinfoProc) { p.Eproc.Ucred.Ngroups = 17 }, func(p *unix.KinfoProc) { p.Eproc.Ucred.Ngroups = 2; p.Eproc.Ucred.Groups[1] = 20 },
	} {
		q := p
		change(&q)
		if darwinIDsMatch(&q, 501, 501) {
			t.Fatal("unexpected authority admitted")
		}
	}
	if darwinIDsMatch(nil, 501, 501) {
		t.Fatal("absent snapshot admitted")
	}
}
