//go:build windows && tracebolt_setup_rust && !cgo

package windowssetupui

// Selecting the experimental frontend without its static link must fail closed,
// never silently fall back to another installer or frontend.
func rustFrontendEnabled() bool   { return true }
func runRust(Config, Hooks) error { return ErrUI }
