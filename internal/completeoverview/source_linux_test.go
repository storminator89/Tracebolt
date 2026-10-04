//go:build linux

package completeoverview

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProcSelfUsesOnlyCanonicalMountPID(t *testing.T) {
	// The caller PID is deliberately unrelated; no actual PID/proc access occurs.
	const callerPID = "7"
	const mountPID = "4242"
	got, e := resolveProcSelf(func(b []byte) (int, error) { return copy(b, mountPID), nil })
	if e != nil || got != mountPID || got == callerPID {
		t.Fatal("proc namespace mixed")
	}
	for _, v := range []string{"", "0", "01", "-1", "+1", "2147483648", "../42", "42/stat", "/42", "42\x00", "42\n", strings.Repeat("1", 64)} {
		if _, e := resolveProcSelf(func(b []byte) (int, error) { return copy(b, v), nil }); e == nil {
			t.Fatal("unsafe self link accepted")
		}
	}
	for _, n := range []int{-1, 64, 65} {
		if _, e := resolveProcSelf(func([]byte) (int, error) { return n, nil }); e == nil {
			t.Fatal("invalid readlink count accepted")
		}
	}
}
func TestDescriptorCeilingReservesExistingSoftLimit(t *testing.T) {
	for _, tc := range []struct {
		soft uint64
		want int
	}{{0, 0}, {128, 0}, {129, 1}, {256, 128}, {1024, 896}, {2048, 1024}, {^uint64(0), 1024}} {
		if descriptorBudget(tc.soft) != tc.want {
			t.Fatal("soft limit reserve not enforced")
		}
	}
}
func TestUnsafeMountAncestorsAndIdentityAreRejected(t *testing.T) {
	mounts := []MountRecord{{MountPoint: "/", Filesystem: "ext4"}, {MountPoint: "/net", Filesystem: "nfs"}, {MountPoint: "/auto", Filesystem: "autofs"}, {MountPoint: "/fuse", Filesystem: "fuse.sshfs"}, {MountPoint: "/unknown", Filesystem: "mystery"}}
	blocked := blockedMountPaths(mounts)
	for _, p := range []string{"/net", "/net/nested/local", "/auto/child", "/fuse/child", "/unknown/child"} {
		if safeMountPath(p, blocked) {
			t.Fatal("unsafe ancestor traversable")
		}
	}
	for _, p := range []string{"/", "/netlike", "/local"} {
		if !safeMountPath(p, blocked) {
			t.Fatal("unrelated path blocked")
		}
	}
	m := MountRecord{MountID: 42, Major: 8, Minor: 1}
	st := unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 42, Dev_major: 8, Dev_minor: 1, Mode: unix.S_IFDIR}
	if !statxMatches(st, m) {
		t.Fatal("fixture identity failed")
	}
	st.Mnt_id = 43
	if statxMatches(st, m) {
		t.Fatal("replaced mount accepted")
	}
	st.Mnt_id = 42
	st.Mode = unix.S_IFLNK
	if statxMatches(st, m) {
		t.Fatal("symlink mount accepted")
	}
	st.Mode = unix.S_IFDIR
	st.Mask = 0
	if statxMatches(st, m) {
		t.Fatal("unavailable mount ID accepted")
	}
}
func TestMountCoherenceChecksEntireSet(t *testing.T) {
	a := []MountRecord{{MountID: 1, Root: "/", Filesystem: "ext4"}, {MountID: 2, Root: "/", Filesystem: "proc"}}
	b := []MountRecord{a[1], a[0]}
	if !sameMounts(a, b) {
		t.Fatal("order incorrectly matters")
	}
	b[1].Root = "/different"
	if sameMounts(a, b) {
		t.Fatal("changed mount identity accepted")
	}
	if sameMounts(a, a[:1]) {
		t.Fatal("missing mount accepted")
	}
}
func TestCumulativeSourceBudgetSyntheticReader(t *testing.T) {
	p := &linuxProvider{sourceBytes: MaxSourceBytes - 2}
	r := &countedReader{ReadCloser: io.NopCloser(bytes.NewReader([]byte("abc"))), owner: p}
	buf := make([]byte, 4)
	if _, e := r.Read(buf); e != ErrSourceLimit {
		t.Fatal("cumulative source bytes not rejected")
	}
}
