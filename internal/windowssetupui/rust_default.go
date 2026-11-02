//go:build !windows || !tracebolt_setup_rust

package windowssetupui

func rustFrontendEnabled() bool   { return false }
func runRust(Config, Hooks) error { return ErrUnsupported }
