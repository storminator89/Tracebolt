//go:build linux

package lanstore

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func privateLeaseDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestManagerWriterLeaseExclusiveWithoutStateFiles(t *testing.T) {
	dir := privateLeaseDirectory(t)
	old := []byte("invented retained revoked/used/consent bytes")
	if err := os.WriteFile(filepath.Join(dir, "retained-state"), old, 0600); err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	if err := lease.Check(); err != nil {
		t.Fatal(err)
	}
	// Advisory directory ownership is not an OS write prohibition: an old
	// binary/manual tool can ignore it. No capture proof follows from this lease.
	if err := os.WriteFile(filepath.Join(dir, "retained-state"), old, 0600); err != nil {
		t.Fatal("source fixture unexpectedly relied on mandatory file locking")
	}
	if other, err := AcquireManagerWriter(dir); err != ErrManagerWriterBusy || other != nil {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("parallel writer was not rejected")
	}
	concrete := lease.(*managerWriterLease)
	flags, err := unix.FcntlInt(concrete.file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("writer lease can leak through exec")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal("repeated close changed result")
	}
	if err := lease.Check(); err != ErrStorage {
		t.Fatal("closed lease remains usable")
	}
	next, err := AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal("closed writer was not released")
	}
	_ = next.Close()
	entries, err := os.ReadDir(dir)
	got, readErr := os.ReadFile(filepath.Join(dir, "retained-state"))
	if err != nil || len(entries) != 1 || readErr != nil || !bytes.Equal(old, got) {
		t.Fatal("lease changed retained bytes or created a lock file")
	}
}

func TestManagerWriterLeaseProcessHelper(t *testing.T) {
	path := os.Getenv("TRACEBOLT_MANAGER_LEASE_FIXTURE")
	if path == "" {
		return
	}
	lease, err := AcquireManagerWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	fmt.Fprintln(os.Stdout, "fixture-writer-held")
	var one [1]byte
	_, _ = os.Stdin.Read(one[:])
}

func TestManagerWriterLeaseSubprocessConflictAndCrash(t *testing.T) {
	dir := privateLeaseDirectory(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestManagerWriterLeaseProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TRACEBOLT_MANAGER_LEASE_FIXTURE="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "fixture-writer-held\n" {
		t.Fatal("isolated writer did not hold its lease")
	}
	if lease, err := AcquireManagerWriter(dir); err != ErrManagerWriterBusy || lease != nil {
		if lease != nil {
			_ = lease.Close()
		}
		t.Fatal("independent-process conflict was not rejected")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	lease, err := AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal("OS lease was not released after isolated crash")
	}
	_ = lease.Close()
}

func TestManagerWriterLeaseProtectedPathsAndQuarantine(t *testing.T) {
	base := privateLeaseDirectory(t)
	dir := filepath.Join(base, "fresh")
	lease, err := AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal("fresh private directory could not be prepared", err)
	}
	_ = lease.Close()
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("fresh lease created state files")
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{alias, filepath.Join(alias, "child"), "relative", dir + "/../fresh"} {
		if l, err := AcquireManagerWriter(path); err != ErrStorage || l != nil {
			if l != nil {
				_ = l.Close()
			}
			t.Fatal("unsafe path accepted")
		}
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if l, err := AcquireManagerWriter(dir); err != ErrStorage || l != nil {
		t.Fatal("public directory adopted")
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("existing mode was changed")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	lease, err = AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := os.Rename(dir, dir+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := lease.Check(); err != ErrStorage {
		t.Fatal("replaced directory was accepted by original lease")
	}
	if err := MarkRestoreQuarantine(dir); err != nil {
		t.Fatal(err)
	}
	if l, err := AcquireManagerWriter(dir); err != ErrRestoreQuarantined || l != nil {
		t.Fatal("quarantine was not retained")
	}
}

func TestManagerWriterLeaseFilesystemBoundary(t *testing.T) {
	for _, kind := range []int64{unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC} {
		if !managerWriterFilesystem(kind) {
			t.Fatal("local locking candidate rejected")
		}
	}
	for _, kind := range []int64{unix.NFS_SUPER_MAGIC, 0xff534d42, 0x65735546, 0x01021997, 0} {
		if managerWriterFilesystem(kind) {
			t.Fatal("remote, FUSE or unknown filesystem accepted")
		}
	}
	for _, err := range []error{unix.EOPNOTSUPP, unix.ENOSYS, unix.EPERM} {
		if !managerWriterUnsupported(err) {
			t.Fatal("unsupported locking mechanism narrowed existing startup compatibility")
		}
	}
	for _, err := range []error{unix.EWOULDBLOCK, unix.EIO, unix.EBADF, unix.EINTR, unix.EINVAL} {
		if managerWriterUnsupported(err) {
			t.Fatal("real contention/storage failure was treated as unsupported")
		}
	}
}
