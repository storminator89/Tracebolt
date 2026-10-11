//go:build !windows

package windowsstorage

import "context"

func nativeDrives(context.Context) (Drives, error) { return Drives{}, ErrUnsupported }
func nativeDisks(context.Context) (Disks, error)   { return Disks{}, ErrUnsupported }
