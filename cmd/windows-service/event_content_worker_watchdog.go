package main

import "time"

// The parent remains authoritative at 10 seconds and synchronously reaps the
// child. This longer child-only timer also bounds an orphaned worker if its
// parent crashes before it can cancel. No target PID or timeout comes from IPC.
const eventContentWorkerOrphanBudget = 15 * time.Second

func armEventContentWorkerWatchdog(budget time.Duration, terminateSelf func()) func() {
	timer := time.AfterFunc(budget, terminateSelf)
	return func() { timer.Stop() }
}
