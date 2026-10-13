package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func admittedHost() (HostContext, map[string]string) {
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt",
		"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "TRACEBOLT_NATIVE_GATE_I": "enabled",
		"TRACEBOLT_REPOSITORY_VISIBILITY": "public", "GITHUB_RUN_ATTEMPT": "1", "TRACEBOLT_RUNNER_LABEL": "macos-15", "RUNNER_ARCH": "ARM64",
		"GITHUB_SHA": strings.Repeat("a", 40), "GITHUB_WORKFLOW_SHA": strings.Repeat("a", 40), "TRACEBOLT_REVIEWED_COMMIT": strings.Repeat("a", 40),
		"TRACEBOLT_REVIEWED_SOURCE_SHA256": strings.Repeat("b", 64),
	}
	return HostContext{"darwin", "arm64", "go1.27.1", true, func(k string) string { return env[k] }}, env
}

func TestAdmissionOnlyExactManualTaggedDarwinContext(t *testing.T) {
	host, env := admittedHost()
	if admission([]string{"--native-interfaces-once"}, host) != "" {
		t.Fatal("fixture admission")
	}
	for key := range env {
		old := env[key]
		env[key] = "unreviewed"
		if admission([]string{"--native-interfaces-once"}, host) == "" {
			t.Fatalf("accepted bad %s", key)
		}
		env[key] = old
	}
	for _, mutate := range []func(*HostContext){
		func(h *HostContext) { h.GOOS = "linux" }, func(h *HostContext) { h.GOARCH = "386" }, func(h *HostContext) { h.GoVersion = "go1.27.0" },
		func(h *HostContext) { h.DiagnosticBuild = false }, func(h *HostContext) { h.Getenv = nil },
	} {
		h := host
		mutate(&h)
		if admission([]string{"--native-interfaces-once"}, h) == "" {
			t.Fatal("bad host accepted")
		}
	}
	host.GOARCH = "amd64"
	env["TRACEBOLT_RUNNER_LABEL"] = "macos-15-intel"
	env["RUNNER_ARCH"] = "X64"
	if admission([]string{"--native-interfaces-once"}, host) != "" {
		t.Fatal("intel fixture")
	}
}

func TestBlockedAndCheckNeverInvokeCommands(t *testing.T) {
	host, _ := admittedHost()
	for _, args := range [][]string{nil, {"--check"}, {"--native-inventory-once"}, {"--native-interfaces-once", "extra"}, {"raw-error-canary"}} {
		var out bytes.Buffer
		exit := Execute(args, host, func(context.Context, bool) ([]byte, error) { t.Fatal("command called"); return nil, nil }, &out)
		if len(args) == 1 && args[0] == "--check" {
			if exit != 0 {
				t.Fatal("check")
			}
		} else if exit != 2 {
			t.Fatal("block")
		}
		if bytes.Contains(out.Bytes(), []byte("raw-error-canary")) {
			t.Fatal("argument leak")
		}
		var r Report
		if json.Unmarshal(out.Bytes(), &r) != nil || !validReport(r) {
			t.Fatal("invalid inert projection")
		}
	}
}

func TestAdmittedExecuteUsesOnlyInjectedCommands(t *testing.T) {
	host, _ := admittedHost()
	calls := 0
	var out bytes.Buffer
	exit := Execute([]string{"--native-interfaces-once"}, host, func(ctx context.Context, ipv6 bool) ([]byte, error) { calls++; return goodCommand(ctx, ipv6) }, &out)
	var r Report
	if exit != 0 || calls != 2 || json.Unmarshal(out.Bytes(), &r) != nil || r.Mode != "native" || !validReport(r) {
		t.Fatal("injected execution")
	}
	assertReport(t, r)
}

type shortWriter struct{ calls int }

func (w *shortWriter) Write(b []byte) (int, error) { w.calls++; return len(b) - 1, nil }

func TestOutputUncertaintyDoesNotRetry(t *testing.T) {
	w := &shortWriter{}
	if Execute([]string{"--check"}, HostContext{}, nil, w) != 1 || w.calls != 1 {
		t.Fatal("write retried")
	}
	if Execute([]string{"--check"}, HostContext{}, nil, nil) != 1 {
		t.Fatal("nil writer")
	}
}

func TestBuildTagsExcludeNativeBridgeByDefault(t *testing.T) {
	root := filepath.Join("..", "..", "..", "internal", "macosinventory")
	for _, osName := range []string{"linux", "darwin"} {
		for _, tagged := range []bool{false, true} {
			ctx := build.Default
			ctx.GOOS = osName
			ctx.BuildTags = nil
			if tagged {
				ctx.BuildTags = []string{"tracebolt_interface_diagnostics"}
			}
			for _, item := range []struct {
				dir, file string
				want      bool
			}{
				{".", "native_enabled.go", osName == "darwin" && tagged}, {".", "native_disabled.go", osName != "darwin" || !tagged},
				{root, "interface_probe.go", tagged}, {root, "interface_probe_darwin.go", osName == "darwin" && tagged},
			} {
				match, err := ctx.MatchFile(item.dir, item.file)
				if err != nil || match != item.want {
					t.Fatalf("build boundary %s/%s tag=%v", osName, item.file, tagged)
				}
			}
		}
	}
}

func TestAdapterHasOneParserCallAndNoBroadCollector(t *testing.T) {
	for _, file := range []string{"main.go", "probe.go", "native_enabled.go", "native_disabled.go"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"CollectNative(", "exec.Command", "os/exec", "net.Dial", "os.Create", "os.WriteFile"} {
			if bytes.Contains(b, []byte(forbidden)) {
				t.Fatalf("broad edge %s", file)
			}
		}
		if file == "probe.go" && bytes.Count(b, []byte("macosinventory.ParseInterfacesWithDiagnostic(")) != 1 {
			t.Fatal("parser duplicated")
		}
	}
}
