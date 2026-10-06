//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/agentinstall"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const readAdminLifecycleLimit = 4096

// Keep one over-limit byte while draining stdout. Diagnostics must neither
// allocate unbounded output nor change a lifecycle command's exit status.
type readAdminBoundedOutput struct{ raw []byte }

func (b *readAdminBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := readAdminLifecycleLimit + 1 - len(b.raw); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.raw = append(b.raw, p...)
	}
	return n, nil
}

func readAdminCaptureLifecycle(cmd *exec.Cmd) ([]byte, error) {
	var output readAdminBoundedOutput
	cmd.Stdout = &output
	err := cmd.Run()
	return output.raw, err
}

type readAdminLifecycleDiagnostic struct {
	failureStage, committed, rolledBack, identityRetained string
}

func readAdminInvalidLifecycle() readAdminLifecycleDiagnostic {
	return readAdminLifecycleDiagnostic{"invalid", "unavailable", "unavailable", "unavailable"}
}

// A closed source vocabulary, including the separately reviewed Restart-only
// bookkeeping reset. A diagnostic label is not permission to perform it.
func readAdminLifecycleStage(stage string) string {
	switch stage {
	case "":
		return "none"
	case "stop_owned_service", "validate_existing_guided_state", "reset_owned_service_restart_state", "start_owned_service", "disable_owned_service", "remove_owned_installation_files", "commit":
		return stage
	}
	if strings.HasPrefix(stage, "preflight_") && systemdInstallerStage(stage) == "installer_"+stage {
		return stage
	}
	return "invalid"
}

// Pure parser for the existing CLI Result, never its plan/body or stderr.
// Re-encoding enforces the exact producer form, rejecting missing/duplicate/
// aliased fields, unknown members and trailing output before projecting flags.
func readAdminParseLifecycle(raw []byte) readAdminLifecycleDiagnostic {
	if len(raw) == 0 || len(raw) > readAdminLifecycleLimit {
		return readAdminInvalidLifecycle()
	}
	var result agentinstall.Result
	if json.Unmarshal(raw, &result) != nil {
		return readAdminInvalidLifecycle()
	}
	canonical, err := json.Marshal(result)
	defer clear(canonical)
	stage := readAdminLifecycleStage(string(result.FailureStage))
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) || stage == "invalid" {
		return readAdminInvalidLifecycle()
	}
	return readAdminLifecycleDiagnostic{stage, strconv.FormatBool(result.Committed), strconv.FormatBool(result.RolledBack), strconv.FormatBool(result.IdentityRetained)}
}

func readAdminParseMaintenanceFailure(raw []byte) readAdminLifecycleDiagnostic {
	d := readAdminInvalidLifecycle()
	if len(raw) == 0 || len(raw) > readAdminLifecycleLimit {
		return d
	}
	var failure struct {
		SchemaVersion string `json:"schemaVersion"`
		FailureStage  string `json:"failureStage"`
	}
	if json.Unmarshal(raw, &failure) == nil && failure.SchemaVersion == "tracebolt.read-admin-result.v2" && failure.FailureStage != "" && readAdminSetupFailure(failure.FailureStage) == failure.FailureStage {
		d.failureStage = failure.FailureStage
	}
	return d
}

type readAdminUnitDiagnostic struct{ activeState, subState, result string }

const readAdminUnitActiveStates = "active reloading inactive failed activating deactivating maintenance refreshing"
const readAdminUnitSubStates = "dead running exited failed auto-restart auto-restart-queued start-pre start start-post stop stop-sigterm stop-sigkill stop-post final-sigterm final-sigkill reload reload-signal reload-notify listening start-chown stop-pre stop-pre-sigterm stop-pre-sigkill"
const readAdminUnitResults = "success resources protocol timeout exit-code signal core-dump watchdog start-limit-hit oom-kill exec-condition skip-condition"

func readAdminUnitLabel(value, allowed string) string {
	for _, label := range strings.Fields(allowed) {
		if value == label {
			return label
		}
	}
	return "unknown"
}

// Pure exact-property parser. Only fixed labels survive; neither an unexpected
// property nor malformed/duplicate output can be mistaken for observed status.
func readAdminParseUnitDiagnostic(raw []byte) readAdminUnitDiagnostic {
	invalid := readAdminUnitDiagnostic{"invalid", "invalid", "invalid"}
	if len(raw) == 0 || len(raw) > readAdminLifecycleLimit {
		return invalid
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "ActiveState" && key != "SubState" && key != "Result" {
			return invalid
		}
		if _, duplicate := values[key]; duplicate {
			return invalid
		}
		values[key] = value
	}
	if len(values) != 3 {
		return invalid
	}
	return readAdminUnitDiagnostic{readAdminUnitLabel(values["ActiveState"], readAdminUnitActiveStates), readAdminUnitLabel(values["SubState"], readAdminUnitSubStates), readAdminUnitLabel(values["Result"], readAdminUnitResults)}
}

func readAdminLifecycleOperation(operation string) string {
	switch operation {
	case "restart_preflight", "restart_apply", "uninstall_cleanup":
		return operation
	case "inspect-socket":
		return "inspect_socket"
	case "revoke-socket":
		return "revoke_socket"
	case "cleanup":
		return "helper_cleanup"
	}
	return ""
}

// Native failure diagnostics only: these read-only samples grant no ownership,
// retry, reset, bypass or permission to change any unit. Teardown stays unchanged.
func readAdminLogLifecycleFailure(t *testing.T, operation string, d readAdminLifecycleDiagnostic) {
	t.Helper()
	operation = readAdminLifecycleOperation(operation)
	if operation == "" {
		return
	}
	for _, unit := range []struct{ label, name string }{
		{"agent", "tracebolt-agent.service"},
		{"socket_helper", "tracebolt-socket-owner-reader.service"},
		{"socket_listener", "tracebolt-socket-owner-reader.socket"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", unit.name, "--property=ActiveState,SubState,Result", "--all", "--no-pager")
		cmd.WaitDelay = time.Second
		cmd.Env = systemdCleanEnvironment()
		raw, err := readAdminCaptureLifecycle(cmd)
		cancel()
		state := readAdminUnitDiagnostic{"unavailable", "unavailable", "unavailable"}
		if err == nil {
			state = readAdminParseUnitDiagnostic(raw)
		}
		clear(raw)
		t.Logf("native_lifecycle operation=%s failureStage=%s committed=%s rolledBack=%s identityRetained=%s unit=%s activeState=%s subState=%s result=%s", operation, d.failureStage, d.committed, d.rolledBack, d.identityRetained, unit.label, state.activeState, state.subState, state.result)
	}
}

func readAdminRunLifecycle(t *testing.T, cmd *exec.Cmd, operation string) error {
	t.Helper()
	raw, err := readAdminCaptureLifecycle(cmd)
	defer clear(raw)
	if err != nil {
		readAdminLogLifecycleFailure(t, operation, readAdminParseLifecycle(raw))
	}
	return err
}
