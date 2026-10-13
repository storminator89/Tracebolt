// Package main is an explicitly tagged, default-off manual diagnostic probe.
package main

import (
	"context"
	"io"
	"os"
	"runtime"
)

// HostContext is injectable for inert admission tests, not authentication.
// main supplies fixed build/runtime facts; the supervisor verifies source.
type HostContext struct {
	GOOS, GOARCH, GoVersion string
	DiagnosticBuild         bool
	Getenv                  func(string) string
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func admission(args []string, host HostContext) string {
	if len(args) != 1 || args[0] != "--native-interfaces-once" {
		return "selector_required"
	}
	if host.GOOS != "darwin" {
		return "unsupported_platform"
	}
	if !host.DiagnosticBuild {
		return "diagnostic_build_required"
	}
	if host.GoVersion != "go1.27.1" {
		return "toolchain_rejected"
	}
	if host.Getenv == nil {
		return "host_context_rejected"
	}
	env := host.Getenv
	for key, value := range map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
		"GITHUB_REPOSITORY": "storminator89/Tracebolt", "RUNNER_ENVIRONMENT": "github-hosted",
		"RUNNER_OS": "macOS", "TRACEBOLT_NATIVE_GATE_I": "enabled", "TRACEBOLT_REPOSITORY_VISIBILITY": "public",
		"GITHUB_RUN_ATTEMPT": "1",
	} {
		if env(key) != value {
			return "host_context_rejected"
		}
	}
	commit := env("TRACEBOLT_REVIEWED_COMMIT")
	if !lowerHex(commit, 40) || env("GITHUB_SHA") != commit || env("GITHUB_WORKFLOW_SHA") != commit ||
		!lowerHex(env("TRACEBOLT_REVIEWED_SOURCE_SHA256"), 64) {
		return "host_context_rejected"
	}
	if !(host.GOARCH == "arm64" && env("TRACEBOLT_RUNNER_LABEL") == "macos-15" && env("RUNNER_ARCH") == "ARM64" ||
		host.GOARCH == "amd64" && env("TRACEBOLT_RUNNER_LABEL") == "macos-15-intel" && env("RUNNER_ARCH") == "X64") {
		return "host_context_rejected"
	}
	return ""
}

// Execute has no discovery, arbitrary command or caller-controlled output path.
func Execute(args []string, host HostContext, command Command, output io.Writer) int {
	r, exit := emptyReport("blocked", "blocked", "selector_required"), 2
	if len(args) == 1 && args[0] == "--check" {
		r, exit = emptyReport("check", "checked", "not_run"), 0
	} else if reason := admission(args, host); reason != "" {
		r.Reason = reason
	} else {
		r = Run(context.Background(), command)
		r.Mode, exit = "native", 1
		if r.Status == "passed" {
			exit = 0
		}
	}
	b, ok := encodeReport(r)
	if !ok || output == nil {
		return 1
	}
	n, err := output.Write(b)
	if err != nil || n != len(b) {
		return 1
	}
	return exit
}

func main() {
	os.Exit(Execute(os.Args[1:], HostContext{runtime.GOOS, runtime.GOARCH, runtime.Version(), diagnosticBuild, os.Getenv}, nativeCommand, os.Stdout))
}
