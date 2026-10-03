//go:build linux

package agentinstall

import (
	"golang.org/x/sys/unix"
	"os"
)

// A replaced FIFO cannot block before the regular-file/fstat checks, and a
// replaced symlink is never followed. The descriptor remains close-on-exec.
func openArtifactFile(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrArtifact
	}
	return os.NewFile(uintptr(fd), "installer-artifact"), nil
}
