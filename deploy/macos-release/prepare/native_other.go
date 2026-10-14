//go:build !darwin || ios

package main

// Host preparation is macOS-only. Linux retains read-only package verification;
// other unsupported hosts reject selected package/bootstrap paths before open.
func newNativeStage() hostStage { return nil }
