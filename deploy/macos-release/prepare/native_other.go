//go:build !darwin

package main

// Verification is portable. Host preparation is intentionally macOS-only.
func newNativeStage() hostStage { return nil }
