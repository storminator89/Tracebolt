package currentsetupgate

import (
	"errors"
	"strings"
	"testing"
)

func TestHiddenInputProbeDistinguishesTerminalAndConsoleFailures(t *testing.T) {
	for _, test := range []struct {
		name, operation, consoleStage, consoleText, want                      string
		exited, processError, finished, consoleError, hidden, ready, terminal bool
	}{
		{name: "process inspection", processError: true, want: "hidden-input-process-inspect", terminal: true},
		{name: "process exit", exited: true, want: "hidden-input-process-exited", terminal: true},
		{name: "compatibility", finished: true, operation: "Manager compatibility check failed before installation: private marker", want: "hidden-input-installer-compatibility", terminal: true},
		{name: "preflight", finished: true, operation: "Setup stopped before installation writes. private marker", want: "hidden-input-installer-before-mutation", terminal: true},
		{name: "installer", finished: true, operation: "Setup stopped. private marker", want: "hidden-input-installer-failed", terminal: true},
		{name: "returned", finished: true, operation: "private marker", want: "hidden-input-installer-returned", terminal: true},
		{name: "bounded text", finished: true, operation: "Setup stopped." + strings.Repeat("x", 64<<10), want: "hidden-input-installer-returned", terminal: true},
		{name: "unknown console diagnostic", consoleError: true, consoleStage: "private marker", want: "hidden-input-console-observation"},
		{name: "echo enabled", consoleText: "invitation in this console (hidden):", want: "hidden-input-echo-enabled"},
		{name: "prompt absent", hidden: true, consoleText: "public trust only", want: "hidden-input-prompt-absent"},
		{name: "partial prompt", hidden: true, consoleText: "invitation in this console", want: "hidden-input-prompt-absent"},
		{name: "real hidden prompt", hidden: true, consoleText: "Verify public trust and enter the invitation in this\r\n console (hidden): ", ready: true, want: "hidden-input"},
	} {
		t.Run(test.name, func(t *testing.T) {
			last := ""
			operationCalls, consoleCalls := 0, 0
			screen, ready, terminal := ProbeHiddenInput(func(s string) { last = s }, HiddenInputSteps{
				Process: func() (bool, error) {
					if test.processError {
						return false, errors.New("private native error")
					}
					return test.exited, nil
				},
				Operation: func() (string, bool) { operationCalls++; return test.operation, test.finished },
				Console: func(stage func(string)) (string, bool, error) {
					consoleCalls++
					stage(test.consoleStage)
					if test.consoleError {
						return test.consoleText, test.hidden, errors.New("private native error")
					}
					return test.consoleText, test.hidden, nil
				},
			})
			if last != test.want || ready != test.ready || terminal != test.terminal {
				t.Fatalf("finite outcome %q ready=%v terminal=%v", last, ready, terminal)
			}
			if !ready && screen != "" || ready && screen != test.consoleText {
				t.Fatal("unexpected screen retention")
			}
			if (test.exited || test.processError) && operationCalls != 0 {
				t.Fatal("operation inspected after terminal process")
			}
			if test.terminal && consoleCalls != 0 {
				t.Fatal("console inspected after terminal observation")
			}
		})
	}
	for _, observation := range []string{"attach", "open-input", "open-output", "mode", "screen-info", "screen-bound", "screen-read", "no-echo"} {
		last := ""
		_, ready, terminal := ProbeHiddenInput(func(s string) { last = s }, HiddenInputSteps{
			Process:   func() (bool, error) { return false, nil },
			Operation: func() (string, bool) { return "", false },
			Console: func(stage func(string)) (string, bool, error) {
				stage("console-" + observation)
				return "private", false, errors.New("private")
			},
		})
		if last != "hidden-input-console-"+observation || ready || terminal {
			t.Fatal("console failure was collapsed or promoted")
		}
	}
}

func TestHiddenInputFailureReportNeverBecomesAcceptance(t *testing.T) {
	_, b, _ := authorized()
	for _, which := range Cases {
		b.Case = which
		for _, stage := range HiddenInputFailureStages {
			r := NewReport(b)
			r.Status, r.Stage, r.Reason = "failed", stage, "operation_failed"
			r.ApprovalValidated, r.NativeActionsAttempted, r.PlatformDisposalRequired = true, true, true
			if r.Validate() != nil {
				t.Fatal("finite failure rejected", stage)
			}
			r.Reason = "inspection_required"
			if r.Validate() != nil {
				t.Fatal("panic-contained failure rejected", stage)
			}
			r.Reason = "operation_failed"
			r.Checks["hiddenConsoleExercised"] = true
			if r.Validate() == nil {
				t.Fatal("failed hidden input promoted")
			}
			r.Checks["hiddenConsoleExercised"] = false
			r.Status = "passed_packaged_gui_subset"
			if r.Validate() == nil {
				t.Fatal("failed stage accepted")
			}
		}
	}
}

func TestHiddenInputInstallerDiagnosticExactFiniteEnvelope(t *testing.T) {
	suffix := "\r\n\r\n" + hiddenInputInterrupted
	before := hiddenInputBeforeMutation + "elevation-required" + suffix
	stopped := "Setup stopped. Package diagnostic: package-failed; service phase: enrollment; reason: input_rejected" + hiddenInputStoppedSuffix + suffix
	for _, test := range []struct{ stage, text, reason string }{
		{"hidden-input-installer-before-mutation", before, "setup_package:elevation-required"},
		{"hidden-input-installer-failed", stopped, "setup_service:package-failed:enrollment:input_rejected"},
	} {
		if got := hiddenInputDiagnostic(test.stage, test.text); got != test.reason {
			t.Fatal("canonical public diagnostic lost")
		}
		for _, bad := range []string{"prefix" + test.text, test.text + "suffix", test.text + test.text, strings.TrimSuffix(test.text, suffix), strings.Replace(test.text, "Package diagnostic: ", "Package diagnostic: private-", 1), strings.Replace(test.text, hiddenInputInterrupted, "Success", 1), strings.Repeat("x", 2049)} {
			if hiddenInputDiagnostic(test.stage, bad) != "" {
				t.Fatal("noncanonical text accepted")
			}
		}
		last, reason := "", "operation_failed"
		_, ready, terminal := ProbeHiddenInput(func(s string) { last = s }, HiddenInputSteps{
			Failure:   func(value string) { reason = value },
			Process:   func() (bool, error) { return false, nil },
			Operation: func() (string, bool) { return test.text, true },
			Console: func(func(string)) (string, bool, error) {
				t.Fatal("read console after installer returned")
				return "", false, nil
			},
		})
		if ready || !terminal || last != test.stage || reason != test.reason {
			t.Fatal("finite diagnostic not retained")
		}
		_, b, _ := authorized()
		for _, which := range Cases {
			b.Case = which
			r := NewReport(b)
			r.Status, r.Stage, r.Reason = "failed", test.stage, reason
			r.ApprovalValidated, r.NativeActionsAttempted, r.PlatformDisposalRequired = true, true, true
			if r.Validate() != nil {
				t.Fatal("finite installer diagnostic rejected")
			}
			r.Stage = "hidden-input-prompt-absent"
			if r.Validate() == nil {
				t.Fatal("installer reason on unrelated stage")
			}
		}
	}
	for _, reason := range []string{"setup_package:private", "setup_service:package-failed:private:input_rejected", "setup_service:package-failed:enrollment:private", "setup_service:package-failed:enrollment:input_rejected:private", "setup_service:msi-bounds:enrollment:input_rejected"} {
		if HiddenInputFailureReason(reason) {
			t.Fatal("nonfinite or unrelated diagnostic")
		}
	}
}
