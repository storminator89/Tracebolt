//go:build linux

package managerstatus

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func filesystemFixture(t *testing.T) (*FilesystemProbe, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private-path-must-not-appear")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("fixture directory failed")
	}
	p, err := NewFilesystemProbe(dir)
	if err != nil {
		t.Fatal("private fixture rejected")
	}
	return p, dir
}

func TestFilesystemProbeAllocatesOnlyBoundedZeroContentAndRecovers(t *testing.T) {
	p, dir := filesystemFixture(t)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("construction wrote state")
	}
	var previous os.FileInfo
	for sample := 0; sample < 4; sample++ {
		got := p.Check(context.Background())
		if got.State != OK || got.Storage == nil || got.Storage.ProbeBytes != filesystemProbeBytes {
			t.Fatal("filesystem operation failed")
		}
		entries, _ = os.ReadDir(dir)
		if len(entries) != 1 || entries[0].Name() != filesystemProbeCurrent {
			t.Fatal("probe footprint is not bounded")
		}
		info, err := os.Lstat(filepath.Join(dir, filesystemProbeCurrent))
		if err != nil || !privateProbeFile(info) || info.Size() != filesystemProbeBytes {
			t.Fatal("probe file invalid")
		}
		if previous != nil && os.SameFile(previous, info) {
			t.Fatal("probe reused the existing diagnostic inode")
		}
		previous = info
	}
	if err := os.WriteFile(filepath.Join(dir, filesystemProbeNext), make([]byte, 127), 0600); err != nil {
		t.Fatal("crash-prefix fixture failed")
	}
	if got := p.Check(context.Background()); got.State != OK {
		t.Fatal("recognized crash-prefix was not recovered")
	}
	if _, err := os.Lstat(filepath.Join(dir, filesystemProbeNext)); !os.IsNotExist(err) {
		t.Fatal("next slot survived completed operation")
	}
	for _, value := range []any{*p, p, p.Check(context.Background())} {
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), dir) || strings.Contains(fmt.Sprintf("%#v", value), dir) {
			t.Fatal("filesystem diagnostics exposed path")
		}
	}
}

func TestFilesystemProbeRejectsReservedPathAdoption(t *testing.T) {
	for _, kind := range []string{"content", "symlink", "hardlink", "public", "short-current", "directory"} {
		t.Run(kind, func(t *testing.T) {
			p, dir := filesystemFixture(t)
			path := filepath.Join(dir, filesystemProbeCurrent)
			outside := filepath.Join(t.TempDir(), "not-probe-authority")
			if err := os.WriteFile(outside, make([]byte, filesystemProbeBytes), 0600); err != nil {
				t.Fatal("fixture failed")
			}
			switch kind {
			case "content":
				if err := os.WriteFile(path, []byte("must-not-be-overwritten"), 0600); err != nil {
					t.Fatal("fixture failed")
				}
			case "symlink":
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal("fixture failed")
				}
			case "hardlink":
				if err := os.Link(outside, path); err != nil {
					t.Fatal("fixture failed")
				}
			case "public":
				if err := os.WriteFile(path, make([]byte, filesystemProbeBytes), 0644); err != nil {
					t.Fatal("fixture failed")
				}
			case "short-current":
				if err := os.WriteFile(path, make([]byte, 7), 0600); err != nil {
					t.Fatal("fixture failed")
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal("fixture failed")
				}
			}
			before, _ := os.Lstat(path)
			if got := p.Check(context.Background()); got.State != Invalid {
				t.Fatal("unrecognized state adopted or overwritten")
			}
			after, _ := os.Lstat(path)
			if !os.SameFile(before, after) || before.Size() != after.Size() {
				t.Fatal("unsafe existing path changed")
			}
			if _, err := os.Lstat(filepath.Join(dir, filesystemProbeNext)); !os.IsNotExist(err) {
				t.Fatal("unsafe path caused another write")
			}
		})
	}
}

func TestFilesystemProbeFailureClassesCancellationAndRecovery(t *testing.T) {
	p, dir := filesystemFixture(t)
	open := p.openNext
	p.openNext = func(string) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: "secret-path-sentinel", Err: syscall.ENOSPC}
	}
	out := p.Check(context.Background())
	if out.State != Full {
		t.Fatal("actual allocation boundary full error was not classified")
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "sentinel") {
		t.Fatal("error text leaked")
	}
	p.openNext = open
	if got := p.Check(context.Background()); got.State != OK {
		t.Fatal("full failure did not recover")
	}
	p.syncFile = func(*os.File) error { return syscall.EDQUOT }
	if got := p.Check(context.Background()); got.State != Full {
		t.Fatal("sync quota failure was not classified")
	}
	if _, err := os.Lstat(filepath.Join(dir, filesystemProbeNext)); !os.IsNotExist(err) {
		t.Fatal("failed sample retained temp file")
	}
	p.syncFile = func(file *os.File) error { return file.Sync() }
	if got := p.Check(context.Background()); got.State != OK {
		t.Fatal("sync failure did not recover")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := p.Check(ctx); got.State != Timeout {
		t.Fatal("canceled probe performed work")
	}
}

func TestFilesystemProbeDirectoryBindingAndConcurrentSampling(t *testing.T) {
	p, dir := filesystemFixture(t)
	p.mu.Lock()
	if got := p.Check(context.Background()); got.State != Busy {
		t.Fatal("probe queued unbounded work")
	}
	p.mu.Unlock()
	if err := os.Rename(dir, dir+"-old"); err != nil {
		t.Fatal("fixture rename failed")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("fixture replacement failed")
	}
	if got := p.Check(context.Background()); got.State != Invalid {
		t.Fatal("replacement directory adopted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("probe wrote into replacement directory")
	}
}

func TestFilesystemProbeNoncooperativeSyncCannotBlockSnapshot(t *testing.T) {
	p, _ := filesystemFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	p.syncFile = func(file *os.File) error { once.Do(func() { close(started); <-release }); return file.Sync() }
	m, err := New([]Check{{Component: Filesystem, Probe: p.Check}}, nil)
	if err != nil {
		t.Fatal("monitor fixture rejected")
	}
	done := make(chan error, 1)
	go func() { done <- m.Refresh(context.Background()) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not start")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked filesystem sync escaped monitor bound")
	}
	if m.Snapshot().Ready {
		t.Fatal("timed-out filesystem operation proved readiness")
	}
	for i := 0; i < 4; i++ {
		_ = m.Refresh(context.Background())
		if m.Snapshot().Ready || m.Snapshot().Components[0].State != Busy {
			t.Fatal("stuck sync spawned or admitted another probe")
		}
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = m.Refresh(context.Background())
		if m.Snapshot().Ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bounded monitor did not recover after late filesystem completion")
}

func TestFilesystemProbeRejectsUnsafeAncestorsAndInvalidNext(t *testing.T) {
	parent := t.TempDir()
	unsafe := filepath.Join(parent, "unsafe-parent")
	if err := os.Mkdir(unsafe, 0777); err != nil {
		t.Fatal("fixture failed")
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal("fixture mode failed")
	}
	dir := filepath.Join(unsafe, "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("fixture failed")
	}
	if _, err := NewFilesystemProbe(dir); err == nil {
		t.Fatal("replaceable ancestor accepted")
	}
	for _, kind := range []string{"content", "symlink", "hardlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			p, dir := filesystemFixture(t)
			if p.Check(context.Background()).State != OK {
				t.Fatal("fixture sample failed")
			}
			current, _ := os.Stat(filepath.Join(dir, filesystemProbeCurrent))
			next := filepath.Join(dir, filesystemProbeNext)
			var err error
			switch kind {
			case "content":
				err = os.WriteFile(next, []byte("not-a-zero-probe"), 0600)
			case "symlink":
				err = os.Symlink(filepath.Join(dir, filesystemProbeCurrent), next)
			case "hardlink":
				err = os.Link(filepath.Join(dir, filesystemProbeCurrent), next)
			case "public":
				err = os.WriteFile(next, make([]byte, 5), 0644)
			}
			if err != nil {
				t.Fatal("invalid next-slot fixture failed")
			}
			if p.Check(context.Background()).State != Invalid {
				t.Fatal("invalid next slot was adopted")
			}
			after, _ := os.Stat(filepath.Join(dir, filesystemProbeCurrent))
			if !os.SameFile(current, after) {
				t.Fatal("invalid next slot replaced known current diagnostic")
			}
		})
	}
}
