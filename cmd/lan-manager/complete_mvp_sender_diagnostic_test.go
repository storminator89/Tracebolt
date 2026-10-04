//go:build linux

package main

import (
	"localrmm/internal/agentloop"
	"strings"
	"testing"
)

// This pure test-only classifier preserves the exact acceptance predicate while
// projecting no event values, observations, source paths, identity or raw errors.
func completeMVPSenderFailure(event agentloop.Event, open bool) string {
	if !open {
		return "complete_native_event_stream_closed"
	}
	switch event.Outcome {
	case agentloop.Success:
	case agentloop.Retryable:
		return "complete_native_outcome_retryable"
	case agentloop.Configuration:
		return "complete_native_outcome_configuration"
	case agentloop.State:
		return "complete_native_outcome_state"
	case agentloop.Revoked:
		return "complete_native_outcome_revoked"
	default:
		return "complete_native_outcome_invalid"
	}
	if event.Metadata.Sequence == 0 {
		return "complete_native_metric_sequence_missing"
	}
	switch event.Metadata.SystemStatus {
	case "acknowledged":
	case "pending_retained":
		return "complete_native_system_pending_retained"
	case "":
		return "complete_native_system_status_missing"
	default:
		return "complete_native_system_status_invalid"
	}
	if event.Metadata.SystemSequence == 0 {
		return "complete_native_system_sequence_missing"
	}
	return ""
}

func TestCompleteMVPSenderFailureCategories(t *testing.T) {
	good := agentloop.Event{Outcome: agentloop.Success, Metadata: agentloop.Metadata{Sequence: 1, SystemStatus: "acknowledged", SystemSequence: 1}}
	cases := []struct {
		name, want string
		open       bool
		change     func(*agentloop.Event)
	}{
		{"success", "", true, func(*agentloop.Event) {}},
		{"closed", "complete_native_event_stream_closed", false, func(*agentloop.Event) {}},
		{"retryable", "complete_native_outcome_retryable", true, func(e *agentloop.Event) { e.Outcome = agentloop.Retryable }},
		{"configuration", "complete_native_outcome_configuration", true, func(e *agentloop.Event) { e.Outcome = agentloop.Configuration }},
		{"state", "complete_native_outcome_state", true, func(e *agentloop.Event) { e.Outcome = agentloop.State }},
		{"revoked", "complete_native_outcome_revoked", true, func(e *agentloop.Event) { e.Outcome = agentloop.Revoked }},
		{"unknown_outcome", "complete_native_outcome_invalid", true, func(e *agentloop.Event) { e.Outcome = "private-fixture-value" }},
		{"metric_sequence", "complete_native_metric_sequence_missing", true, func(e *agentloop.Event) { e.Metadata.Sequence = 0 }},
		{"pending", "complete_native_system_pending_retained", true, func(e *agentloop.Event) { e.Metadata.SystemStatus = "pending_retained" }},
		{"missing_status", "complete_native_system_status_missing", true, func(e *agentloop.Event) { e.Metadata.SystemStatus = "" }},
		{"unknown_status", "complete_native_system_status_invalid", true, func(e *agentloop.Event) { e.Metadata.SystemStatus = "private-fixture-value" }},
		{"system_sequence", "complete_native_system_sequence_missing", true, func(e *agentloop.Event) { e.Metadata.SystemSequence = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := good
			tc.change(&e)
			got := completeMVPSenderFailure(e, tc.open)
			originalAccepted := tc.open && e.Outcome == agentloop.Success && e.Metadata.Sequence != 0 && e.Metadata.SystemStatus == "acknowledged" && e.Metadata.SystemSequence != 0
			if got != tc.want || (got == "") != originalAccepted || strings.Contains(got, "private-fixture") {
				t.Fatal("sender failure category or acceptance changed")
			}
		})
	}
}
