//go:build linux

package main

import "golang.org/x/sys/unix"

func serviceProcessIDs(uid, gid int) bool {
	r, e, s := unix.Getresuid()
	gr, ge, gs := unix.Getresgid()
	return r == uid && e == uid && s == uid && gr == gid && ge == gid && gs == gid
}
