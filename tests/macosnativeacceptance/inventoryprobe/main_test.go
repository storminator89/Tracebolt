package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"localrmm/internal/macosinventory"
)

func hostedFixture() (HostContext, map[string]string) {
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt",
		"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "TRACEBOLT_RUNNER_LABEL": "macos-15",
		"TRACEBOLT_NATIVE_GATE_A": "enabled", "TRACEBOLT_REPOSITORY_VISIBILITY": "public",
	}
	return HostContext{"darwin", "arm64", "go1.27.1", func(key string) string { return env[key] }}, env
}

func executeFixture(t *testing.T, args []string, host HostContext, provider Provider) (Report, int) {
	t.Helper()
	var output bytes.Buffer
	code := Execute(args, host, provider, &output)
	var report Report
	if json.Unmarshal(output.Bytes(), &report) != nil || !validReport(report) {
		t.Fatal("boundary did not emit closed JSON")
	}
	assertSafe(t, report)
	return report, code
}

func TestCheckDoesNotReadEnvironmentOrProvider(t *testing.T) {
	host := HostContext{Getenv: func(string) string { t.Fatal("check read host environment"); return "" }}
	provider := func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error) {
		t.Fatal("check invoked provider")
		return macosinventory.Snapshot{}, nil
	}
	report, code := executeFixture(t, []string{"--check"}, host, provider)
	if code != 0 || report.Mode != "check" || report.Status != "checked" || report.CollectionCalls != 0 {
		t.Fatal("check claimed execution")
	}
}

func TestExplicitSelectorRequired(t *testing.T) {
	host, _ := hostedFixture()
	for _, args := range [][]string{nil, {}, {"--native"}, {"--check", "--native-inventory-once"}, {"--native-inventory-once", "/bin/ps"}, {"--native-inventory-once=true"}, {"--native-inventory-once", "--native-inventory-once"}, {"--help"}} {
		report, code := executeFixture(t, args, host, func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error) {
			t.Fatal("unselected/ambiguous caller command invoked provider")
			return macosinventory.Snapshot{}, nil
		})
		if code != 2 || report.Status != "blocked" || report.CollectionCalls != 0 {
			t.Fatal("selector did not fail closed")
		}
	}
}

func TestHostedGuardRejectsEveryMissingOrAlteredMarker(t *testing.T) {
	_, original := hostedFixture()
	for key := range original {
		for _, value := range []string{"", "SECRET"} {
			t.Run(key+value, func(t *testing.T) {
				host, env := hostedFixture()
				env[key] = value
				report, code := executeFixture(t, []string{"--native-inventory-once"}, host, func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error) {
					t.Fatal("incorrect hosted context invoked provider")
					return macosinventory.Snapshot{}, nil
				})
				if code != 2 || report.Reason != "host_context_rejected" {
					t.Fatal("host guard accepted changed marker")
				}
			})
		}
	}
}

func TestRuntimeGuardRejectsNonDarwinArchitectureAndToolchain(t *testing.T) {
	for _, mutate := range []func(*HostContext){
		func(h *HostContext) { h.GOOS = "linux" },
		func(h *HostContext) { h.GOOS = "windows" },
		func(h *HostContext) { h.GOARCH = "amd64" },
		func(h *HostContext) { h.GOARCH = "386" },
		func(h *HostContext) { h.GoVersion = "go1.27.0" },
		func(h *HostContext) { h.Getenv = nil },
	} {
		host, _ := hostedFixture()
		mutate(&host)
		_, code := executeFixture(t, []string{"--native-inventory-once"}, host, func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error) {
			t.Fatal("runtime guard invoked provider")
			return macosinventory.Snapshot{}, nil
		})
		if code != 2 {
			t.Fatal("runtime guard accepted invalid host")
		}
	}
}

func TestInjectedBoundaryCallsOnceAndFailedGateNonzero(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, failed := range []bool{false, true} {
			host, env := hostedFixture()
			if arch == "amd64" {
				host.GOARCH, env["TRACEBOLT_RUNNER_LABEL"], env["RUNNER_ARCH"] = arch, "macos-15-intel", "X64"
			}
			calls := 0
			report, code := executeFixture(t, []string{"--native-inventory-once"}, host, func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
				calls++
				if failed {
					return macosinventory.Snapshot{}, errors.New("SECRET")
				}
				return fixtureProvider(ctx, req)
			})
			if calls != 1 || report.CollectionCalls != 1 || (failed && code != 1) || (!failed && code != 0) {
				t.Fatal("boundary retried or provider failure produced successful exit")
			}
		}
	}
}

type failedWriter struct{ calls int }

func (w *failedWriter) Write(p []byte) (int, error) {
	w.calls++
	return len(p) / 2, errors.New("SECRET writer error")
}

func TestOutputFailureDoesNotRetryOrPrintError(t *testing.T) {
	w := new(failedWriter)
	if Execute([]string{"--check"}, HostContext{}, nil, w) != 1 || w.calls != 1 {
		t.Fatal("output failure retried or passed")
	}
}
