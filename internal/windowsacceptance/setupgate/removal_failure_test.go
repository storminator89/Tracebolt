package setupgate

import (
	"localrmm/internal/windowsservice"
	"strings"
	"testing"
)

func removalText(step, reason string) string {
	return "Service removal did not complete. Removal diagnostic: " + step + "; " + reason + ". Files, identity and grants remain; inspect retained state before any further action.\r\n\r\n" + uninstallInterrupted
}
func TestRemovalFailureParserExactEnvelopeAndPairs(t *testing.T) {
	for _, stage := range RemovalFailureStages {
		for _, reason := range []string{"failed", "canceled", "access_denied", "service:service_apply_stop_control:failed:access_denied"} {
			s, r, ok := ParseRemovalFailure(removalText(strings.TrimPrefix(stage, "uninstall-failure-"), reason))
			if !ok || s != stage || r != reason {
				t.Fatal("finite failure rejected")
			}
		}
	}
	good := removalText("stop", "failed")
	for _, bad := range []string{"prefix" + good, good + "suffix", good + "\r\n" + good, strings.Replace(good, "; failed", "; private", 1), strings.Replace(good, "stop;", "foreign;", 1), strings.Replace(good, uninstallInterrupted, uninstallCompleted, 1), removalText("stop", "service:service_owned_context:failed:failed"), removalText("stop", "service:service_apply_stop_control:failed:private"), removalText("stop", "service:unknown:unknown:failed"), strings.Repeat("x", 2049), strings.Replace(good, "stop;", "stop; injected;", 1)} {
		if _, _, ok := ParseRemovalFailure(bad); ok {
			t.Fatal("untrusted envelope accepted")
		}
	}
}
func TestRemovalFailureReportCannotGrantAcceptance(t *testing.T) {
	_, b, _ := authorized()
	reasons := []string{"failed", "receipt_rejected", "canceled", "deadline", "access_denied", "cannot_accept_control", "not_active", "dependent_services", "delete_pending"}
	for _, pair := range windowsservice.SetupDiagnosticPairs() {
		if pair[0] != "unknown" {
			reasons = append(reasons, "service:"+pair[0]+":"+pair[1]+":failed")
		}
	}
	for _, stage := range RemovalFailureStages {
		for _, reason := range reasons {
			r := NewReport(b)
			r.Status = "failed"
			r.Stage = stage
			r.Reason = reason
			r.ApprovalValidated = true
			r.NativeActionsAttempted = true
			r.PlatformDisposalRequired = true
			if r.Validate() != nil {
				t.Fatalf("valid failure rejected: %s %s", stage, reason)
			}
			for _, status := range []string{"blocked", "passed_packaged_gui_subset"} {
				bad := r
				bad.Status = status
				if bad.Validate() == nil {
					t.Fatal("failure diagnostic accepted as success/block")
				}
			}
			for _, which := range []string{"pending-transport", "cancel-hidden-input"} {
				bad := NewReport(Binding{Source: b.Source, Case: which})
				bad = r
				bad.Case = which
				bad.Checks = map[string]bool{}
				for _, check := range Checks[which] {
					bad.Checks[check] = false
				}
				if bad.Validate() == nil {
					t.Fatal("non-removal case accepted")
				}
			}
		}
	}
}
