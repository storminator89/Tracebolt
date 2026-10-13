package main

import (
	"context"
	"io"
	"os"
	"runtime"

	"localrmm/internal/macosinventory"
)

// HostContext contains only runtime constants and explicit workflow markers.
// It is a default-off accident guard, not authentication or execution approval.
// The supervisor separately verifies source, image, identity, and task custody.
type HostContext struct {
	GOOS, GOARCH, GoVersion string
	Getenv                  func(string) string
}

func admission(args []string, host HostContext) string {
	if len(args) != 1 || args[0] != "--native-inventory-once" {
		return "selector_required"
	}
	if host.GOOS != "darwin" {
		return "unsupported_platform"
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
		"RUNNER_OS": "macOS", "TRACEBOLT_NATIVE_GATE_A": "enabled", "TRACEBOLT_REPOSITORY_VISIBILITY": "public",
	} {
		if env(key) != value {
			return "host_context_rejected"
		}
	}
	if !(host.GOARCH == "arm64" && env("TRACEBOLT_RUNNER_LABEL") == "macos-15" && env("RUNNER_ARCH") == "ARM64" ||
		host.GOARCH == "amd64" && env("TRACEBOLT_RUNNER_LABEL") == "macos-15-intel" && env("RUNNER_ARCH") == "X64") {
		return "host_context_rejected"
	}
	return ""
}

// Execute is injected for inert boundary tests. It never discovers providers or
// accepts caller command strings, output paths, real consent, or credentials.
func Execute(args []string, host HostContext, provide Provider, output io.Writer) int {
	report := emptyReport("blocked", "blocked", "selector_required")
	exit := 2
	if len(args) == 1 && args[0] == "--check" {
		report = emptyReport("check", "checked", "not_run")
		exit = 0
	} else if reason := admission(args, host); reason != "" {
		report.Reason = reason
	} else {
		report = Run(context.Background(), provide)
		report.Mode = "native"
		exit = 1
		if report.Status == "passed" {
			exit = 0
		}
	}
	encoded, ok := encodeReport(report)
	if !ok || output == nil {
		return 1
	}
	// One bounded write, no logging, formatted errors, or retry on uncertainty.
	n, err := output.Write(encoded)
	if err != nil || n != len(encoded) {
		return 1
	}
	return exit
}

func nativeProvider(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
	// Defense in depth: even direct calls cannot invoke a provider on non-Darwin.
	if runtime.GOOS != "darwin" {
		return macosinventory.Snapshot{}, macosinventory.ErrUnsupported
	}
	return macosinventory.CollectNative(ctx, req)
}

func main() {
	os.Exit(Execute(os.Args[1:], HostContext{runtime.GOOS, runtime.GOARCH, runtime.Version(), os.Getenv}, nativeProvider, os.Stdout))
}
