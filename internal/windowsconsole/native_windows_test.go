//go:build windows

package windowsconsole

import (
	"testing"

	"golang.org/x/sys/windows"
)

// This is a pure constants test, not a native console interaction.
func TestNativeModeConstants(t *testing.T) {
	if processedInput != windows.ENABLE_PROCESSED_INPUT || lineInput != windows.ENABLE_LINE_INPUT ||
		echoInput != windows.ENABLE_ECHO_INPUT || quickEdit != windows.ENABLE_QUICK_EDIT_MODE ||
		extendedFlags != windows.ENABLE_EXTENDED_FLAGS || virtualInput != windows.ENABLE_VIRTUAL_TERMINAL_INPUT ||
		consoleReadNowait != 0x0002 {
		t.Fatal("native console constants mismatch")
	}
}
