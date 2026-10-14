//go:build (darwin && !ios) || (linux && !android)

package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openSelectedRegular(name string, limit int64) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" {
		return nil, errRejected
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRejected
	}
	defer func() { _ = unix.Close(dir) }()
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, errRejected
		}
		next, e := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return nil, errRejected
		}
		_ = unix.Close(dir)
		dir = next
	}
	leaf := parts[len(parts)-1]
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, errRejected
	}
	fd, err := unix.Openat(dir, leaf, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRejected
	}
	f := os.NewFile(uintptr(fd), "reviewed-input")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size <= 0 || st.Size > limit {
		_ = f.Close()
		return nil, errRejected
	}
	return f, nil
}
