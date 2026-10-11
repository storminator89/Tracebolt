package main

import "time"

// The parent remains authoritative at 15 seconds and synchronously reaps the
// child. This longer child-only timer also bounds an orphaned worker if its
// parent crashes before it can cancel. No target PID or timeout comes from IPC.
const updatesWorkerOrphanBudget = 20 * time.Second

func armUpdatesWorkerWatchdog(budget time.Duration, terminateSelf func()) func() {
	timer := time.AfterFunc(budget, terminateSelf)
	return func() { timer.Stop() }
}
