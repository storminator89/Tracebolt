//go:build linux

package windowsupdateexecutor

import "syscall"

func testThreadID() uint64 { return uint64(syscall.Gettid()) }
