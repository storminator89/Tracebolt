package currentsetupgate

import (
	"localrmm/internal/windowsservice"
	"strings"
)

// HiddenInputFailureStages describe only observations before invitation entry.
// They contain neither native error strings nor GUI/console text. An attach
// failure does not prove that Setup allocated a console or reached enrollment.
var HiddenInputFailureStages = []string{
	"hidden-input-process-inspect", "hidden-input-process-exited",
	"hidden-input-installer-compatibility", "hidden-input-installer-before-mutation",
	"hidden-input-installer-failed", "hidden-input-installer-returned",
	"hidden-input-console-observation", "hidden-input-console-attach",
	"hidden-input-console-open-input", "hidden-input-console-open-output",
	"hidden-input-console-mode", "hidden-input-console-screen-info",
	"hidden-input-console-screen-bound", "hidden-input-console-screen-read",
	"hidden-input-console-no-echo", "hidden-input-echo-enabled", "hidden-input-prompt-absent",
}

type HiddenInputSteps struct {
	Failure func(reason string)

	Process   func() (exited bool, err error)
	Operation func() (text string, finished bool)
	Console   func(stage func(string)) (text string, hidden bool, err error)
}

// ProbeHiddenInput is one read-only observation, never a wait, launch or retry.
// Its native caller keeps the existing 40-second deadline and requires both the
// real console's no-echo mode and actual invitation prompt. Only terminal process
// or completed-wizard observations can end that wait early, always as failures.
func ProbeHiddenInput(stage func(string), s HiddenInputSteps) (screen string, ready, terminal bool) {
	stage("hidden-input-process-inspect")
	exited, err := s.Process()
	if err != nil {
		return "", false, true
	}
	if exited {
		stage("hidden-input-process-exited")
		return "", false, true
	}
	text, finished := s.Operation()
	if finished {
		failure := "hidden-input-installer-returned"
		// setupText already bounds native GUI reads. Repeat the bound at the
		// portable classifier and match only the package's fixed public markers.
		if len(text) <= 64<<10 {
			switch {
			case strings.HasPrefix(text, "Manager compatibility check failed before installation:"):
				failure = "hidden-input-installer-compatibility"
			case strings.HasPrefix(text, "Setup stopped before installation writes."):
				failure = "hidden-input-installer-before-mutation"
			case strings.HasPrefix(text, "Setup stopped.") || strings.Contains(text, "The operation did not complete."):
				failure = "hidden-input-installer-failed"
			}
		}
		stage(failure)
		if reason := hiddenInputDiagnostic(failure, text); reason != "" && s.Failure != nil {
			s.Failure(reason)
		}
		return "", false, true
	}
	stage("hidden-input-console-observation")
	text, hidden, err := s.Console(func(observation string) {
		value := "hidden-input-" + observation
		if Contains(HiddenInputFailureStages, value) && strings.HasPrefix(observation, "console-") {
			stage(value)
		} else {
			stage("hidden-input-console-observation")
		}
	})
	if err != nil {
		return "", false, false
	}
	if !hidden {
		stage("hidden-input-echo-enabled")
		return "", false, false
	}
	if !strings.Contains(strings.Join(strings.Fields(text), " "), "invitation in this console (hidden):") {
		stage("hidden-input-prompt-absent")
		return "", false, false
	}
	stage("hidden-input")
	return text, true, false
}

// Only the fixed package diagnostics reachable from fresh package provisioning
// are admitted; optional MSI/update domains and arbitrary native strings are not.
var hiddenInputPackageCodes = []string{"absence-unverified", "ancestor-ace", "ancestor-dacl", "ancestor-descriptor", "ancestor-open", "ancestor-owner", "ancestor-writer", "architecture-invalid", "architecture-mismatch", "bootstrap-size", "cancelled", "close-failed", "created-descriptor", "descriptor-create", "descriptor-query", "directory-case", "directory-create", "elevation-required", "elevation-unverified", "existing-resource", "existing-service", "file-create", "file-digest", "file-duplicate", "file-flush", "file-handle", "file-pin", "file-read", "file-size", "file-streams", "file-write", "filesystem-unsupported", "layout-invalid", "manifest-invalid", "object-kind", "object-metadata", "object-reparse", "object-role", "package-failed", "package-incomplete", "path-binding", "payload-digest", "payload-machine", "payload-pe", "payload-size", "service-inspection", "unsupported-platform"}

const hiddenInputBeforeMutation = "Setup stopped before installation writes. No new service, identity or scope grants were created. Review the package, platform, public export and existing-installation boundary; existing state is never overwritten or repaired. Package diagnostic: "
const hiddenInputStoppedSuffix = ". Retained state may be incomplete or startup indeterminate. Do not rerun installation or delete state. An administrator can use the installed tracebolt-windows-service.exe --inspect for read-only SCM status; retain the displayed public diagnostic for review."
const hiddenInputInterrupted = "The operation did not complete. Durable changes may exist; files, identity and state are retained. Inspect the retained state before any further action. This wizard will not retry or reset it."

// HiddenInputFailureReason validates finite values without using free-form text.
func HiddenInputFailureReason(reason string) bool {
	parts := strings.Split(reason, ":")
	if len(parts) < 2 || !Contains(hiddenInputPackageCodes, parts[1]) {
		return false
	}
	if len(parts) == 2 {
		return parts[0] == "setup_package"
	}
	if len(parts) != 4 || parts[0] != "setup_service" {
		return false
	}
	d := windowsservice.Diagnostic(windowsservice.Mark(windowsservice.Phase(parts[2]), windowsservice.Reason(parts[3]), ErrGuard))
	return string(d.Phase) == parts[2] && string(d.Reason) == parts[3]
}

func hiddenInputDiagnostic(stage, text string) string {
	suffix := "\r\n\r\n" + hiddenInputInterrupted
	if len(text) > 2048 || !strings.HasSuffix(text, suffix) {
		return ""
	}
	text = strings.TrimSuffix(text, suffix)
	reason := ""
	switch stage {
	case "hidden-input-installer-before-mutation":
		if !strings.HasPrefix(text, hiddenInputBeforeMutation) {
			return ""
		}
		reason = "setup_package:" + strings.TrimPrefix(text, hiddenInputBeforeMutation)
	case "hidden-input-installer-failed":
		const prefix = "Setup stopped. Package diagnostic: "
		if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, hiddenInputStoppedSuffix) {
			return ""
		}
		body := strings.TrimSuffix(strings.TrimPrefix(text, prefix), hiddenInputStoppedSuffix)
		parts := strings.Split(body, "; ")
		if len(parts) != 3 || !strings.HasPrefix(parts[1], "service phase: ") || !strings.HasPrefix(parts[2], "reason: ") {
			return ""
		}
		reason = "setup_service:" + parts[0] + ":" + strings.TrimPrefix(parts[1], "service phase: ") + ":" + strings.TrimPrefix(parts[2], "reason: ")
	}
	if !HiddenInputFailureReason(reason) {
		return ""
	}
	return reason
}
