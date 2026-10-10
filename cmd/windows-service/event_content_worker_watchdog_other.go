//go:build !windows

package main

func startEventContentWorkerWatchdog() func() { return func() {} }
