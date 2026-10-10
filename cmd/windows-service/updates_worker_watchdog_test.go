package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestUpdatesWorkerWatchdogUsesOnlyInjectedTermination(t *testing.T) {
	fired := make(chan struct{})
	stop := armUpdatesWorkerWatchdog(time.Millisecond, func() { close(fired) })
	defer stop()
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not fire")
	}
	clean := make(chan struct{}, 1)
	stop = armUpdatesWorkerWatchdog(20*time.Millisecond, func() { clean <- struct{}{} })
	stop()
	select {
	case <-clean:
		t.Fatal("clean worker terminated")
	case <-time.After(40 * time.Millisecond):
	}
	if updatesWorkerOrphanBudget <= 15*time.Second || updatesWorkerOrphanBudget > 30*time.Second {
		t.Fatal("unbounded orphan grace")
	}
}
func TestUpdatesWorkerNativeWatchdogCannotTargetAnotherProcess(t *testing.T) {
	raw, err := os.ReadFile("updates_worker_watchdog_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if !strings.Contains(source, "windows.TerminateProcess(windows.CurrentProcess(), 1)") || strings.Contains(source, "OpenProcess(") || strings.Contains(source, "os.Exit(") {
		t.Fatal("watchdog is not current-process-only")
	}
}
