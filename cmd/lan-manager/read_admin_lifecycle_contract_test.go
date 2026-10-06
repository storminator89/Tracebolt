//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/agentinstall"
	"strings"
	"testing"
)

func TestReadAdminLifecycleResultIsClosed(t *testing.T) {
	result := agentinstall.Result{FailureStage: agentinstall.OpStart, RolledBack: true, IdentityRetained: true}
	raw, _ := json.Marshal(result)
	want := readAdminLifecycleDiagnostic{"start_owned_service", "false", "true", "true"}
	if got := readAdminParseLifecycle(append(raw, '\n')); got != want {
		t.Fatal("existing lifecycle result projection lost")
	}
	for _, stage := range []string{"preflight_inspect", "preflight_begin_lock", "stop_owned_service", "validate_existing_guided_state", "reset_owned_service_restart_state", "start_owned_service", "disable_owned_service", "remove_owned_installation_files", "commit", ""} {
		result.FailureStage = agentinstall.Operation(stage)
		encoded, _ := json.Marshal(result)
		got := readAdminParseLifecycle(encoded)
		if got.failureStage == "invalid" || got.identityRetained != "true" {
			t.Fatal("closed lifecycle stage lost")
		}
	}
	for _, invalid := range [][]byte{
		nil, []byte(`{}`), append(append([]byte{}, raw...), []byte(`{}`)...),
		bytes.Replace(raw, []byte(`"committed":false`), []byte(`"committed":false,"committed":true`), 1),
		bytes.Replace(raw, []byte(`"committed":false`), []byte(`"committed":null`), 1),
		bytes.Replace(raw, []byte(`"committed":false,`), nil, 1),
		bytes.Replace(raw, []byte(`"committed":false`), []byte(`"Committed":false`), 1),
		bytes.Replace(raw, []byte(`"failureStage":"start_owned_service"`), []byte(`"failureStage":"private-secret"`), 1),
		bytes.Replace(raw, []byte(`"committed":false`), []byte(`"committed":false,"raw":"private-secret"`), 1),
		append(append([]byte{}, raw...), bytes.Repeat([]byte(" "), readAdminLifecycleLimit)...),
	} {
		if got := readAdminParseLifecycle(invalid); got != readAdminInvalidLifecycle() {
			t.Fatal("unknown lifecycle output was not fixed invalid")
		}
	}
	for _, invalid := range []string{"preflight_private", "private-secret", "start-limit-hit"} {
		if readAdminLifecycleStage(invalid) != "invalid" {
			t.Fatal("arbitrary lifecycle stage retained")
		}
	}
}

func TestReadAdminLifecycleCaptureIsBounded(t *testing.T) {
	var output readAdminBoundedOutput
	input := bytes.Repeat([]byte("x"), 65536)
	for i := 0; i < 3; i++ {
		n, err := output.Write(input)
		if n != len(input) || err != nil || len(output.raw) != readAdminLifecycleLimit+1 {
			t.Fatal("diagnostic capture changed write result or exceeded bound")
		}
	}
}

func TestReadAdminLifecycleUnitStatusIsClosed(t *testing.T) {
	raw := []byte("ActiveState=failed\nSubState=failed\nResult=start-limit-hit\n")
	if got := readAdminParseUnitDiagnostic(raw); got != (readAdminUnitDiagnostic{"failed", "failed", "start-limit-hit"}) {
		t.Fatal("observed start-limit result lost")
	}
	if got := readAdminParseUnitDiagnostic([]byte("Result=success\nSubState=running\nActiveState=active\n")); got != (readAdminUnitDiagnostic{"active", "running", "success"}) {
		t.Fatal("healthy unit result rewritten as failure")
	}
	for _, invalid := range [][]byte{
		nil, []byte("ActiveState=failed\nSubState=failed\n"),
		append(append([]byte{}, raw...), []byte("Result=success\n")...),
		append(append([]byte{}, raw...), []byte("MainPID=123\n")...),
		[]byte(strings.Repeat("x", readAdminLifecycleLimit+1)),
	} {
		if got := readAdminParseUnitDiagnostic(invalid); got != (readAdminUnitDiagnostic{"invalid", "invalid", "invalid"}) {
			t.Fatal("unknown unit output accepted")
		}
	}
	if got := readAdminParseUnitDiagnostic([]byte("ActiveState=private\nSubState=/private/path\nResult=token\n")); got != (readAdminUnitDiagnostic{"unknown", "unknown", "unknown"}) {
		t.Fatal("private unit data leaked")
	}
}

func TestReadAdminMaintenanceLifecycleFailureIsClosed(t *testing.T) {
	for _, stage := range []string{"loaded-unit-ownership", "maintenance-operation-failed", "fixed-unit-status"} {
		if readAdminSetupFailure(stage) != stage {
			continue
		}
		raw := []byte(`{"schemaVersion":"tracebolt.read-admin-result.v2","failureStage":"` + stage + `"}`)
		if got := readAdminParseMaintenanceFailure(raw); got != (readAdminLifecycleDiagnostic{stage, "unavailable", "unavailable", "unavailable"}) {
			t.Fatal("maintenance diagnostic altered lifecycle flags")
		}
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"schemaVersion":"tracebolt.read-admin-result.v2","failureStage":"private-secret"}`), []byte(strings.Repeat("x", readAdminLifecycleLimit+1))} {
		if readAdminParseMaintenanceFailure(raw) != readAdminInvalidLifecycle() {
			t.Fatal("private maintenance output retained")
		}
	}
	for _, op := range []string{"restart_preflight", "restart_apply", "uninstall_cleanup", "inspect-socket", "revoke-socket", "cleanup"} {
		if readAdminLifecycleOperation(op) == "" {
			t.Fatal("fixed lifecycle operation lost")
		}
	}
	if readAdminLifecycleOperation("private-path-or-command") != "" {
		t.Fatal("arbitrary lifecycle operation retained")
	}
}
