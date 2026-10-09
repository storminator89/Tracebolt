package setupgate

import "strings"

// These are exact existing public GUI paragraphs, not error messages or native
// result codes. Text is reduced to finite labels and is never retained.
const uninstallInterrupted = "The operation did not complete. Durable changes may exist; files, identity and state are retained. Inspect the retained state before any further action. This wizard will not retry or reset it."
const uninstallCompleted = "Service removal completed. Installed files, identity and state are retained. Manager identity has not been revoked."
const uninstallStopping = "Stopping the exact receipt-owned service once. Files, identity and grants will remain."
const uninstallRemoving = "Requesting removal of the owned, stopped service. Waiting for SCM to confirm absence."

func uninstallParagraph(text, expected string) bool {
	if len(text) > 32<<10 {
		return false
	}
	for _, paragraph := range strings.Split(text, "\r\n\r\n") {
		if paragraph == expected {
			return true
		}
	}
	return false
}

// UninstallPendingObservation preserves the original controller's read order:
// pending text, successful held-handle status query, stopped, then not Close.
// Its finite diagnostics do not confer success or replace any later assertion.
type UninstallPendingObservation struct {
	pending, stopped, closed bool
	status                   UninstallHeldStatus
}

// UninstallHeldStatus describes only a fixed native query outcome. Unknown
// values fail closed and never become labels or native numbers in a report.
type UninstallHeldStatus uint8

const (
	UninstallStatusFailed UninstallHeldStatus = iota
	UninstallStatusObserved
	UninstallStatusDeletePending
	UninstallStatusInvalidHandle
	UninstallStatusAccessDenied
)

func ObserveUninstallPending(pending bool, status func() (UninstallHeldStatus, bool), closed func() bool) UninstallPendingObservation {
	o := UninstallPendingObservation{pending: pending, closed: true}
	if !pending || status == nil {
		return o
	}
	o.status, o.stopped = status()
	if o.status != UninstallStatusObserved || !o.stopped || closed == nil {
		return o
	}
	o.closed = closed()
	return o
}

func (o UninstallPendingObservation) Ready() bool {
	return o.pending && o.status == UninstallStatusObserved && o.stopped && !o.closed
}

func (o UninstallPendingObservation) Stage(text string) string {
	if !o.pending {
		switch {
		case uninstallParagraph(text, uninstallInterrupted):
			return "uninstall-operation-failed"
		case uninstallParagraph(text, uninstallStopping):
			return "uninstall-stopping"
		case uninstallParagraph(text, uninstallRemoving):
			return "uninstall-removing"
		default:
			return "uninstall-pending-text"
		}
	}
	if o.status != UninstallStatusObserved {
		switch o.status {
		case UninstallStatusDeletePending:
			return "uninstall-held-status-delete-pending"
		case UninstallStatusInvalidHandle:
			return "uninstall-held-status-invalid-handle"
		case UninstallStatusAccessDenied:
			return "uninstall-held-status-access-denied"
		default:
			return "uninstall-held-status"
		}
	}
	if !o.stopped {
		return "uninstall-held-stopped"
	}
	if o.closed {
		if uninstallParagraph(text, uninstallInterrupted) {
			return "uninstall-pending-close-failed"
		}
		if uninstallParagraph(text, uninstallCompleted) {
			return "uninstall-pending-close-completed"
		}
		return "uninstall-pending-close"
	}
	return "uninstall"
}

// Close is displayed on both success and failure. This only diagnoses an
// already-rejected Close during the original 500 ms held-handle observation.
func UninstallHeldCloseStage(text string) string {
	if uninstallParagraph(text, uninstallInterrupted) {
		return "uninstall-held-close-failed"
	}
	if uninstallParagraph(text, uninstallCompleted) {
		return "uninstall-held-close-completed"
	}
	return "uninstall-held-close"
}
