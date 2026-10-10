//go:build !windows

package main

func startUpdatesWorkerWatchdog() func() { return func() {} }
