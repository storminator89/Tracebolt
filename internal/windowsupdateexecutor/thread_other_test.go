//go:build !linux && !windows

package windowsupdateexecutor

func testThreadID() uint64 { return 1 }
