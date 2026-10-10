package setupgate

import (
	"localrmm/internal/windowsservice"
	"strings"
)

var RemovalFailureStages = []string{"uninstall-failure-unknown", "uninstall-failure-validate", "uninstall-failure-context", "uninstall-failure-receipt", "uninstall-failure-owned", "uninstall-failure-state", "uninstall-failure-stop", "uninstall-failure-stop-observe", "uninstall-failure-stop-state", "uninstall-failure-stop-wait", "uninstall-failure-pre-delete", "uninstall-failure-delete", "uninstall-failure-delete-result", "uninstall-failure-absence-inspect", "uninstall-failure-absence-owned", "uninstall-failure-absence-wait"}

func RemovalFailureReason(reason string) bool {
	if Contains([]string{"failed", "receipt_rejected", "canceled", "deadline", "access_denied", "cannot_accept_control", "not_active", "dependent_services", "delete_pending"}, reason) {
		return true
	}
	p := strings.Split(reason, ":")
	return len(p) == 4 && p[0] == "service" && p[1] != "unknown" && windowsservice.SetupDiagnosticValid(p[1], p[2]) && Contains([]string{"failed", "canceled", "deadline", "access_denied", "cannot_accept_control", "not_active", "dependent_services", "delete_pending"}, p[3])
}

// Decode only the complete fixed failure rendering, including the UI's failure
// paragraph. Prefix/suffix text, duplicate lines, unknown pairs and success
// renderings are not authority. Raw text never leaves this function.
func ParseRemovalFailure(text string) (stage, reason string, ok bool) {
	const prefix = "Service removal did not complete. Removal diagnostic: "
	const suffix = ". Files, identity and grants remain; inspect retained state before any further action.\r\n\r\n"
	if len(text) > 2048 || !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix+uninstallInterrupted) {
		return "", "", false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(text, prefix), suffix+uninstallInterrupted)
	parts := strings.Split(body, "; ")
	if len(parts) != 2 {
		return "", "", false
	}
	stage = "uninstall-failure-" + parts[0]
	reason = parts[1]
	if !Contains(RemovalFailureStages, stage) || !RemovalFailureReason(reason) {
		return "", "", false
	}
	return stage, reason, true
}
