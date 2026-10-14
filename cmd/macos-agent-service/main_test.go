package main

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/macosservice"
	"strings"
	"testing"
)

type fakeBackend struct {
	calls  int
	err    error
	checks []macosservice.Check
}

func (b *fakeBackend) Inspect(context.Context, macosservice.Request) ([]macosservice.Check, error) {
	b.calls++
	return b.checks, b.err
}
func args() []string {
	return []string{"--service-identity", "510:510", "--agent-sha256", strings.Repeat("a", 64), "--source-archive", "/Library/Reviewed/source.tar", "--source-sha256", strings.Repeat("b", 64)}
}
func TestRenderOnlyCLIAndHelpDoNotReadHost(t *testing.T) {
	for _, a := range [][]string{append(args(), "--render-only"), {"--help"}, {"-h"}} {
		b := &fakeBackend{err: macosservice.ErrPreflight}
		var out, errOut bytes.Buffer
		if run(context.Background(), a, &out, &errOut, b) != 0 || b.calls != 0 {
			t.Fatal("unexpected inspection")
		}
		if len(a) > 1 {
			var result macosservice.Result
			if json.Unmarshal(out.Bytes(), &result) != nil || result.LocalChecksPerformed || result.InstallationAvailable || result.ReadyForInstallation || result.Plist == "" {
				t.Fatal("misleading result")
			}
		}
	}
}
func TestCLIRefusesMutationAndSecretsBeforeInspection(t *testing.T) {
	for _, bad := range []string{"--apply", "--action=restart", "--launchctl", "--insecure-http-test", "--invitation-secret=DO-NOT-PRINT", "--config=/Users/me/agent.json", "--agent-binary=/bin/sh"} {
		b := &fakeBackend{}
		var out, errOut bytes.Buffer
		if run(context.Background(), append(args(), bad), &out, &errOut, b) != 2 || b.calls != 0 || out.Len() != 0 || strings.Contains(errOut.String(), "DO-NOT-PRINT") {
			t.Fatalf("bad request leaked or executed: %s", bad)
		}
	}
}
func TestDefaultCLIInspectsAndReportsBlocker(t *testing.T) {
	b := &fakeBackend{err: macosservice.ErrPreflight, checks: []macosservice.Check{{Code: "service-identity", Passed: false, Detail: "fixture blocked"}}}
	var out, errOut bytes.Buffer
	if run(context.Background(), args(), &out, &errOut, b) != 1 || b.calls != 1 {
		t.Fatal("preflight not performed")
	}
	var result macosservice.Result
	if json.Unmarshal(out.Bytes(), &result) != nil || !result.LocalChecksPerformed || result.LocalPreflightPassed || result.ReadyForInstallation {
		t.Fatal("misleading failure")
	}
	if !strings.Contains(errOut.String(), "blocked") {
		t.Fatal("missing failure guidance")
	}
}

func TestInstallNativeUnavailableWithoutAnyHostInspection(t *testing.T) {
	for _, extra := range [][]string{{"--action", "install"}, {"--action", "install", "--apply"}} {
		b := &fakeBackend{}
		var out, errOut bytes.Buffer
		if run(context.Background(), append(args(), extra...), &out, &errOut, b) != 1 || b.calls != 0 {
			t.Fatal("unavailable inspected host")
		}
		var result macosservice.InstallResult
		if json.Unmarshal(out.Bytes(), &result) != nil || result.Status != "unavailable" || result.AdapterAvailable || result.MutationAttempted || result.NativeAcceptanceVerified || !strings.Contains(errOut.String(), "unavailable") {
			t.Fatal("misleading availability")
		}
	}
}
func TestUninstallUnavailableBackendNeverInspects(t *testing.T) {
	for _, extra := range [][]string{{"--action", "uninstall"}, {"--action", "uninstall", "--apply"}} {
		b := &fakeBackend{}
		var out, errOut bytes.Buffer
		if run(context.Background(), append(args(), extra...), &out, &errOut, b) != 1 || b.calls != 0 {
			t.Fatal("unavailable removal inspected host")
		}
		var result macosservice.InstallResult
		if json.Unmarshal(out.Bytes(), &result) != nil || result.Status != "unavailable" || result.AdapterAvailable || result.MutationAttempted || result.NativeAcceptanceVerified {
			t.Fatal("misleading removal availability")
		}
	}
}
func TestProfileSelectionAndInvalidCombinations(t *testing.T) {
	for _, extra := range [][]string{{"--profile", "read-admin"}, {"--action", "install", "--render-only"}, {"--apply", "--render-only"}, {"--action", "restart"}} {
		b := &fakeBackend{}
		var out, errOut bytes.Buffer
		if run(context.Background(), append(args(), extra...), &out, &errOut, b) != 2 || b.calls != 0 {
			t.Fatal("invalid selection inspected")
		}
	}
	b := &fakeBackend{}
	var out, errOut bytes.Buffer
	if run(context.Background(), append(args(), "--profile", macosservice.InventoryProfile, "--render-only"), &out, &errOut, b) != 0 || b.calls != 0 {
		t.Fatal("inventory render")
	}
	var result macosservice.Result
	if json.Unmarshal(out.Bytes(), &result) != nil || result.CollectionProfile != macosservice.InventoryProfile || !strings.Contains(result.Plist, "1m0s") {
		t.Fatal("inventory cadence")
	}
}
