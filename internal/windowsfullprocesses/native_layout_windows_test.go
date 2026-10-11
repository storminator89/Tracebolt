//go:build windows

package windowsfullprocesses

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

// Inert layout verification only; this does not read host processes.
func TestFixedNativeEntryFitsDeclaredWorkBound(t *testing.T) {
	var entry windows.ProcessEntry32
	if unsafe.Sizeof(entry) > NativeEntryWorkBytes || len(entry.ExeFile) != NativeNameUnits {
		t.Fatal("native layout exceeds declared fixed work")
	}
}
