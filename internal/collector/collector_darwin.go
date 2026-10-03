//go:build darwin

package collector

import (
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/model"
)

type darwinNativeProvider struct{}

// Snapshot reads only four fixed read-only sysctl keys and statfs("/"). It
// never runs commands, enumerates processes or accesses a user-supplied path.
func Snapshot() model.Device {
	d := snapshotMacOS(darwinNativeProvider{}, time.Now().UTC())
	d.LastSeen = time.Now().UTC()
	return d
}

func (darwinNativeProvider) productVersion() (string, error) {
	return unix.Sysctl("kern.osproductversion")
}

func (darwinNativeProvider) kernelRelease() (string, error) {
	return unix.Sysctl("kern.osrelease")
}

func (darwinNativeProvider) bootTime() (*bootTimeValue, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil || tv == nil {
		return nil, err
	}
	return &bootTimeValue{seconds: tv.Sec, microseconds: int64(tv.Usec)}, nil
}

func (darwinNativeProvider) totalMemory() (*uint64, error) {
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return nil, err
	}
	return &total, nil
}

func (darwinNativeProvider) rootFilesystem() (*filesystemCapacity, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs("/", &fs); err != nil {
		return nil, err
	}
	// The other returned fields (mount source, owner, filesystem identifier)
	// are deliberately discarded rather than being exposed as inventory.
	return &filesystemCapacity{blocks: fs.Blocks, free: fs.Bfree, blockSize: uint64(fs.Bsize)}, nil
}
