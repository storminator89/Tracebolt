//go:build linux

package managerstatus

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const filesystemProbeBytes = 4096
const filesystemProbeCurrent = ".manager-filesystem-write"
const filesystemProbeNext = ".manager-filesystem-write-next"

func privateProbeDirectory(directory string) (os.FileInfo, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrFilesystemProbe
	}
	var direct os.FileInfo
	for path := directory; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrFilesystemProbe
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
			return nil, ErrFilesystemProbe
		}
		if direct == nil {
			if stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
				return nil, ErrFilesystemProbe
			}
			direct = info
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, ErrFilesystemProbe
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	return direct, nil
}

func newFilesystemProbe(directory string) (*FilesystemProbe, error) {
	info, err := privateProbeDirectory(directory)
	if err != nil {
		return nil, ErrFilesystemProbe
	}
	return &FilesystemProbe{mu: &sync.Mutex{}, directory: directory, original: info, openNext: func(path string) (*os.File, error) { return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) }, syncFile: func(file *os.File) error { return file.Sync() }}, nil
}

func privateProbeFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 0 || info.Size() > filesystemProbeBytes {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

// recognizedProbeFile never follows links or adopts arbitrary existing data.
// A crash may leave a zero-filled prefix, including an empty newly created file.
func recognizedProbeFile(path string) (os.FileInfo, error) {
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !privateProbeFile(before) {
		return nil, ErrFilesystemProbe
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrFilesystemProbe
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !privateProbeFile(opened) || !os.SameFile(before, opened) {
		return nil, ErrFilesystemProbe
	}
	raw, err := io.ReadAll(io.LimitReader(file, filesystemProbeBytes+1))
	if err != nil || len(raw) != int(opened.Size()) {
		return nil, ErrFilesystemProbe
	}
	for _, value := range raw {
		if value != 0 {
			return nil, ErrFilesystemProbe
		}
	}
	after, err := os.Lstat(path)
	if err != nil || !privateProbeFile(after) || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return nil, ErrFilesystemProbe
	}
	return after, nil
}

func (p *FilesystemProbe) directoryCurrent() bool {
	info, err := privateProbeDirectory(p.directory)
	return err == nil && os.SameFile(p.original, info)
}

func filesystemSpace(path string) (*StorageMetrics, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return nil, err
	}
	if stat.Bsize <= 0 || stat.Bavail > math.MaxUint64/uint64(stat.Bsize) {
		return nil, ErrFilesystemProbe
	}
	return &StorageMetrics{AvailableBytes: stat.Bavail * uint64(stat.Bsize), FreeInodes: stat.Ffree, ProbeBytes: filesystemProbeBytes}, nil
}

func (p *FilesystemProbe) checkFilesystem(ctx context.Context) ProbeResult {
	if p == nil || p.mu == nil || ctx == nil {
		return ProbeResult{State: Invalid}
	}
	if !p.mu.TryLock() {
		return ProbeResult{State: Busy}
	}
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ProbeResult{State: Classify(err)}
	}
	if !p.directoryCurrent() {
		return ProbeResult{State: Invalid}
	}
	space, err := filesystemSpace(p.directory)
	if err != nil {
		return ProbeResult{State: Classify(err)}
	}
	out := ProbeResult{State: OK, Storage: space}
	if space.AvailableBytes < filesystemProbeBytes {
		out.State = Full
		return out
	}
	currentPath, nextPath := filepath.Join(p.directory, filesystemProbeCurrent), filepath.Join(p.directory, filesystemProbeNext)
	current, err := recognizedProbeFile(currentPath)
	if err != nil || current != nil && current.Size() != filesystemProbeBytes {
		out.State = Invalid
		return out
	}
	next, err := recognizedProbeFile(nextPath)
	if err != nil {
		out.State = Invalid
		return out
	}
	if next != nil {
		if err = os.Remove(nextPath); err != nil {
			out.State = Classify(err)
			return out
		}
	}
	if err = ctx.Err(); err != nil {
		out.State = Classify(err)
		return out
	}
	file, err := p.openNext(nextPath)
	if err != nil {
		out.State = Classify(err)
		return out
	}
	defer func() {
		own, statErr := file.Stat()
		_ = file.Close()
		if statErr == nil {
			if live, pathErr := os.Lstat(nextPath); pathErr == nil && os.SameFile(own, live) {
				_ = os.Remove(nextPath)
			}
		}
	}()
	created, err := file.Stat()
	if err != nil || !privateProbeFile(created) || created.Size() != 0 {
		out.State = Invalid
		return out
	}
	// Unlink/recreate avoids merely overwriting the existing diagnostic inode.
	// Compression/deduplication and allocator behavior may still avoid physical
	// block allocation. Success proves only this exact create/write/fsync call.
	if n, writeErr := file.Write(make([]byte, filesystemProbeBytes)); writeErr != nil || n != filesystemProbeBytes {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		out.State = Classify(writeErr)
		return out
	}
	if err = p.syncFile(file); err != nil {
		out.State = Classify(err)
		return out
	}
	if err = ctx.Err(); err != nil {
		out.State = Classify(err)
		return out
	}
	liveNext, err := os.Lstat(nextPath)
	if err != nil || !privateProbeFile(liveNext) || liveNext.Size() != filesystemProbeBytes || !os.SameFile(created, liveNext) || !p.directoryCurrent() {
		out.State = Invalid
		return out
	}
	liveCurrent, pathErr := os.Lstat(currentPath)
	if current == nil && !os.IsNotExist(pathErr) || current != nil && (pathErr != nil || !os.SameFile(current, liveCurrent)) {
		out.State = Invalid
		return out
	}
	directory, err := os.Open(p.directory)
	if err != nil {
		out.State = Classify(err)
		return out
	}
	defer directory.Close()
	if descriptor, statErr := directory.Stat(); statErr != nil || !os.SameFile(p.original, descriptor) {
		out.State = Invalid
		return out
	}
	if err = os.Rename(nextPath, currentPath); err != nil {
		out.State = Classify(err)
		return out
	}
	if err = directory.Sync(); err != nil {
		out.State = Classify(err)
		return out
	}
	if !p.directoryCurrent() {
		out.State = Invalid
		return out
	}
	if err = ctx.Err(); err != nil {
		out.State = Classify(err)
		return out
	}
	if after, statErr := filesystemSpace(p.directory); statErr == nil {
		out.Storage = after
	} else {
		out.State = Classify(statErr)
	}
	return out
}
