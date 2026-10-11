//go:build windows

package main

import "golang.org/x/sys/windows"

func startEventContentWorkerWatchdog() func() {
	return armEventContentWorkerWatchdog(eventContentWorkerOrphanBudget, func() {
		// ExitProcess (including os.Exit) can deadlock in DLL-detach callbacks
		// when another blocked native thread held a required lock. Terminate
		// only this isolated current process, without running DLL detach.
		_ = windows.TerminateProcess(windows.CurrentProcess(), 1)
	})
}
