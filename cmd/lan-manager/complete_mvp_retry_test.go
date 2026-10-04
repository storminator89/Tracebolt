//go:build linux

package main

import (
	"context"
	"localrmm/internal/agentloop"
	"testing"
	"time"
)

// This test-only tracker accounts for every Finished attempt, including staged
// but unacknowledged domains. It is kept across process restarts; the separate
// manager-validated observations retain the last successful source timestamps.
type completeMVPDomainProgress struct {
	sequence uint64
	pending  bool
}

func (p *completeMVPDomainProgress) record(sequence uint64, retried, pending bool) bool {
	if sequence == 0 {
		return true
	} // An early failure reports no known sequence.
	if sequence == p.sequence {
		if !p.pending || !retried {
			return false
		}
	} else if p.sequence == ^uint64(0) || sequence != p.sequence+1 || p.pending {
		return false
	}
	p.sequence, p.pending = sequence, pending
	return true
}

type completeMVPSenderProgress struct {
	metrics, system   completeMVPDomainProgress
	inventorySequence uint64
}

func (p completeMVPSenderProgress) counters() [3]uint64 {
	return [3]uint64{p.metrics.sequence, p.system.sequence, p.inventorySequence}
}
func (p *completeMVPSenderProgress) record(event agentloop.Event, open bool) (bool, string) {
	if !open {
		return false, "complete_native_event_stream_closed"
	}
	if event.Phase != agentloop.Finished {
		return false, "complete_native_event_phase_invalid"
	}
	if event.Outcome != agentloop.Success && event.Outcome != agentloop.Retryable {
		return false, completeMVPSenderFailure(event, true)
	}
	m := event.Metadata
	validOverview := func(status string, sequence uint64) bool {
		switch status {
		case "":
			return sequence == 0
		case "disabled", "not_due", "pending_retained":
			return true
		case "acknowledged", "failure_acknowledged", "aborted":
			return sequence > 0
		default:
			return false
		}
	}
	if !validOverview(m.ProcessesStatus, m.ProcessesSequence) || !validOverview(m.VolumesStatus, m.VolumesSequence) || m.OverviewOperations > 64 || m.ProcessesStatus == "" && m.VolumesStatus == "" && m.OverviewOperations != 0 || (m.ProcessesStatus != "" || m.VolumesStatus != "") && m.InventoryStatus == "" {
		return false, "complete_native_retry_metadata_invalid"
	}
	switch m.JournalStatus {
	case "", "disabled", "denied", "unavailable", "state_unavailable", "idle", "result_lost", "expired", "helper_unavailable", "pending_retained", "acknowledged":
	default:
		return false, "complete_native_retry_metadata_invalid"
	}
	if m.DiscardedStale || m.SystemDiscardedStale {
		return false, "complete_native_discarded_stale"
	}
	if m.Sequence == 0 && (m.Duplicate || m.AvailablePercentageFields != 0 || m.UnavailablePercentageFields != 0) {
		return false, "complete_native_retry_metadata_invalid"
	}
	if m.AvailablePercentageFields > 3 || m.UnavailablePercentageFields > 3 || int(m.AvailablePercentageFields)+int(m.UnavailablePercentageFields) > 3 || m.InventoryOperations > 64 {
		return false, "complete_native_retry_metadata_invalid"
	}
	switch m.SystemStatus {
	case "":
		if m.SystemSequence != 0 || m.SystemRetriedPending || m.InventoryStatus != "" {
			return false, "complete_native_retry_metadata_invalid"
		}
	case "pending_retained":
		if m.Sequence == 0 || m.InventoryStatus != "" {
			return false, "complete_native_retry_metadata_invalid"
		}
	case "acknowledged":
		if m.Sequence == 0 || m.SystemSequence == 0 {
			return false, "complete_native_retry_metadata_invalid"
		}
	default:
		return false, "complete_native_system_status_invalid"
	}
	switch m.InventoryStatus {
	case "":
		if m.InventorySequence != 0 || m.InventoryOperations != 0 || m.SystemStatus == "acknowledged" {
			return false, "complete_native_retry_metadata_invalid"
		}
	case "not_due":
		if m.SystemStatus != "acknowledged" || m.InventorySequence != 0 || m.InventoryOperations != 0 || p.inventorySequence == 0 {
			return false, "complete_native_retry_metadata_invalid"
		}
	case "pending_retained":
		if m.SystemStatus != "acknowledged" {
			return false, "complete_native_retry_metadata_invalid"
		}
	case "acknowledged", "failure_acknowledged":
		if m.SystemStatus != "acknowledged" || m.InventorySequence == 0 {
			return false, "complete_native_retry_metadata_invalid"
		}
	default:
		return false, "complete native package status contract"
	}
	if event.Outcome == agentloop.Success {
		if category := completeMVPSenderFailure(event, true); category != "" {
			return false, category
		}
		if m.InventoryStatus == "" {
			return false, "complete native package status contract"
		}
	}
	next := *p
	if !next.metrics.record(m.Sequence, m.RetriedPending, event.Outcome == agentloop.Retryable && m.SystemStatus == "") {
		return false, "complete_native_metric_progress_invalid"
	}
	if !next.system.record(m.SystemSequence, m.SystemRetriedPending, m.SystemStatus == "pending_retained") {
		return false, "complete_native_system_progress_invalid"
	}
	// All gate processes share the six-hour package cooldown, well beyond the
	// unchanged two-minute profile and seven-minute aggregate contexts.
	if m.InventorySequence != 0 {
		if m.InventorySequence != 1 {
			return false, "complete_native_package_progress_invalid"
		}
		next.inventorySequence = m.InventorySequence
	}
	*p = next
	return event.Outcome == agentloop.Success, ""
}
func completeMVPWait(ctx context.Context, events <-chan agentloop.Event, progress *completeMVPSenderProgress) (agentloop.Event, string) {
	for {
		if ctx.Err() != nil {
			return agentloop.Event{}, "complete native report deadline"
		}
		select {
		case event, open := <-events:
			if ctx.Err() != nil {
				return agentloop.Event{}, "complete native report deadline"
			}
			ready, category := progress.record(event, open)
			if category != "" {
				return agentloop.Event{}, category
			}
			if ready {
				return event, ""
			}
		case <-ctx.Done():
			return agentloop.Event{}, "complete native report deadline"
		}
	}
}
func completeRetryEvent(outcome agentloop.Outcome, metric, system uint64, systemStatus, inventoryStatus string) agentloop.Event {
	e := agentloop.Event{Phase: agentloop.Finished, Outcome: outcome, Metadata: agentloop.Metadata{Sequence: metric, SystemSequence: system, SystemStatus: systemStatus, InventoryStatus: inventoryStatus}}
	if inventoryStatus == "acknowledged" || inventoryStatus == "pending_retained" {
		e.Metadata.InventorySequence = 1
		e.Metadata.InventoryOperations = 1
	}
	return e
}
func TestCompleteMVPProgressAccountsEveryRetryDomain(t *testing.T) {
	for _, stage := range []string{"metrics", "system", "packages"} {
		t.Run(stage, func(t *testing.T) {
			p := completeMVPSenderProgress{}
			failed := completeRetryEvent(agentloop.Retryable, 1, 0, "", "")
			good := completeRetryEvent(agentloop.Success, 1, 1, "acknowledged", "acknowledged")
			switch stage {
			case "metrics":
				good.Metadata.RetriedPending = true
			case "system":
				failed.Metadata.SystemStatus = "pending_retained"
				failed.Metadata.SystemSequence = 1
				good.Metadata.Sequence = 2
				good.Metadata.SystemRetriedPending = true
			case "packages":
				failed = completeRetryEvent(agentloop.Retryable, 1, 1, "acknowledged", "pending_retained")
				good.Metadata.Sequence = 2
				good.Metadata.SystemSequence = 2
			}
			if ready, category := p.record(failed, true); ready || category != "" {
				t.Fatal("supported retry rejected")
			}
			if ready, category := p.record(good, true); !ready || category != "" {
				t.Fatal("exact retry completion rejected")
			}
			if p.metrics.sequence != good.Metadata.Sequence || p.system.sequence != good.Metadata.SystemSequence || p.metrics.pending || p.system.pending || p.inventorySequence != 1 {
				t.Fatal("retry tracker lost independent floors")
			}
			// Process counters reset externally, but durable domain tracking does not.
			restarted := completeRetryEvent(agentloop.Success, good.Metadata.Sequence+1, good.Metadata.SystemSequence+1, "acknowledged", "not_due")
			if ready, category := p.record(restarted, true); !ready || category != "" {
				t.Fatal("restart did not advance known domains")
			}
		})
	}
}
func TestCompleteMVPProgressRepeatedAndZeroMetadataRetry(t *testing.T) {
	p := completeMVPSenderProgress{}
	pending := completeRetryEvent(agentloop.Retryable, 1, 1, "pending_retained", "")
	if _, category := p.record(pending, true); category != "" {
		t.Fatal(category)
	}
	before := p
	if ready, category := p.record(completeRetryEvent(agentloop.Retryable, 0, 0, "", ""), true); ready || category != "" || p != before {
		t.Fatal("unknown early metadata reset progress")
	}
	repeated := completeRetryEvent(agentloop.Retryable, 2, 1, "pending_retained", "")
	repeated.Metadata.SystemRetriedPending = true
	if ready, category := p.record(repeated, true); ready || category != "" {
		t.Fatal("repeat retained system rejected")
	}
	good := completeRetryEvent(agentloop.Success, 3, 1, "acknowledged", "acknowledged")
	good.Metadata.SystemRetriedPending = true
	if ready, category := p.record(good, true); !ready || category != "" {
		t.Fatal("retained system completion rejected")
	}
	// A retry at the next metric stage may repeat only its newly staged metric.
	metric := completeRetryEvent(agentloop.Retryable, 4, 0, "", "")
	if _, category := p.record(metric, true); category != "" {
		t.Fatal(category)
	}
	metric.Metadata.RetriedPending = true
	if _, category := p.record(metric, true); category != "" {
		t.Fatal("metric retained repeat rejected")
	}
	good = completeRetryEvent(agentloop.Success, 4, 2, "acknowledged", "not_due")
	good.Metadata.RetriedPending = true
	if ready, category := p.record(good, true); !ready || category != "" {
		t.Fatal("metric retained completion rejected")
	}
}
func TestCompleteMVPProgressRejectsInvalidAndFatalEvents(t *testing.T) {
	good := completeRetryEvent(agentloop.Success, 1, 1, "acknowledged", "acknowledged")
	cases := []struct {
		name   string
		change func(*agentloop.Event)
	}{
		{"phase", func(e *agentloop.Event) { e.Phase = agentloop.Starting }},
		{"unknown overview", func(e *agentloop.Event) { e.Metadata.ProcessesStatus = "private-fixture" }},
		{"unknown journal", func(e *agentloop.Event) { e.Metadata.JournalStatus = "private-fixture" }},
		{"overview unbound", func(e *agentloop.Event) { e.Metadata.ProcessesStatus = "acknowledged" }},
		{"overview operations", func(e *agentloop.Event) { e.Metadata.OverviewOperations = 65 }},
		{"configuration", func(e *agentloop.Event) { e.Outcome = agentloop.Configuration }},
		{"state", func(e *agentloop.Event) { e.Outcome = agentloop.State }},
		{"revoked", func(e *agentloop.Event) { e.Outcome = agentloop.Revoked }},
		{"unknown outcome", func(e *agentloop.Event) { e.Outcome = "private-fixture" }},
		{"metric zero", func(e *agentloop.Event) { e.Metadata.Sequence = 0 }},
		{"system zero", func(e *agentloop.Event) { e.Metadata.SystemSequence = 0 }},
		{"metric jump", func(e *agentloop.Event) { e.Metadata.Sequence = 2 }},
		{"system jump", func(e *agentloop.Event) { e.Metadata.SystemSequence = 2 }},
		{"metric stale", func(e *agentloop.Event) { e.Metadata.DiscardedStale = true }},
		{"system stale", func(e *agentloop.Event) { e.Metadata.SystemDiscardedStale = true }},
		{"unknown system", func(e *agentloop.Event) { e.Metadata.SystemStatus = "private-fixture" }},
		{"unknown packages", func(e *agentloop.Event) { e.Metadata.InventoryStatus = "private-fixture" }},
		{"missing system", func(e *agentloop.Event) { e.Metadata.SystemStatus = "" }},
		{"missing packages", func(e *agentloop.Event) { e.Metadata.InventoryStatus = "" }},
		{"package recapture", func(e *agentloop.Event) { e.Metadata.InventorySequence = 2 }},
		{"operations overflow", func(e *agentloop.Event) { e.Metadata.InventoryOperations = 65 }},
		{"counts overflow", func(e *agentloop.Event) { e.Metadata.AvailablePercentageFields = 4 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := completeMVPSenderProgress{}
			e := good
			tc.change(&e)
			if ready, category := p.record(e, true); ready || category == "" || p != (completeMVPSenderProgress{}) {
				t.Fatal("invalid event accepted or changed tracker")
			}
		})
	}
	p := completeMVPSenderProgress{}
	if _, category := p.record(good, true); category != "" {
		t.Fatal(category)
	}
	before := p
	good.Metadata.RetriedPending = true
	good.Metadata.SystemRetriedPending = true
	if ready, category := p.record(good, true); ready || category == "" || p != before {
		t.Fatal("acknowledged domains allowed a fabricated repeat")
	}
}
func TestCompleteMVPWaitRequiresSuccessAndRespectsDeadline(t *testing.T) {
	p := completeMVPSenderProgress{}
	events := make(chan agentloop.Event, 2)
	events <- completeRetryEvent(agentloop.Retryable, 1, 0, "", "")
	good := completeRetryEvent(agentloop.Success, 1, 1, "acknowledged", "acknowledged")
	good.Metadata.RetriedPending = true
	events <- good
	got, category := completeMVPWait(context.Background(), events, &p)
	if category != "" || got != good {
		t.Fatal("bounded wait returned retry as success")
	}
	close(events)
	if _, category = completeMVPWait(context.Background(), events, &p); category != "complete_native_event_stream_closed" {
		t.Fatal("closed stream accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events = make(chan agentloop.Event, 1)
	events <- good
	if _, category = completeMVPWait(ctx, events, &p); category != "complete native report deadline" {
		t.Fatal("deadline ignored for ready event")
	}
}

func TestCompleteMVPProgressRejectsLostPendingOrUnexplainedRepeat(t *testing.T) {
	for _, domain := range []string{"metrics", "system"} {
		for _, fault := range []string{"missing retained flag", "advance pending", "regression", "repeat acknowledged"} {
			t.Run(domain+"/"+fault, func(t *testing.T) {
				p := completeMVPSenderProgress{}
				first := completeRetryEvent(agentloop.Success, 1, 1, "acknowledged", "acknowledged")
				if _, category := p.record(first, true); category != "" {
					t.Fatal(category)
				}
				pending := completeRetryEvent(agentloop.Retryable, 2, 0, "", "")
				if domain == "system" {
					pending = completeRetryEvent(agentloop.Retryable, 2, 2, "pending_retained", "")
				}
				if fault != "repeat acknowledged" {
					if _, category := p.record(pending, true); category != "" {
						t.Fatal(category)
					}
				}
				bad := completeRetryEvent(agentloop.Success, 2, 2, "acknowledged", "not_due")
				if domain == "metrics" {
					bad.Metadata.RetriedPending = true
				} else {
					bad.Metadata.Sequence = 3
					bad.Metadata.SystemRetriedPending = true
				}
				switch fault {
				case "missing retained flag":
					bad.Metadata.RetriedPending = false
					bad.Metadata.SystemRetriedPending = false
				case "advance pending":
					if domain == "metrics" {
						bad.Metadata.Sequence = 3
					} else {
						bad.Metadata.SystemSequence = 3
					}
				case "regression":
					if domain == "metrics" {
						bad.Metadata.Sequence = 1
					} else {
						bad.Metadata.SystemSequence = 1
					}
				case "repeat acknowledged":
					if domain == "metrics" {
						bad.Metadata.Sequence = 1
					} else {
						bad.Metadata.Sequence = 2
						bad.Metadata.SystemSequence = 1
					}
				}
				before := p
				if ready, category := p.record(bad, true); ready || category == "" || p != before {
					t.Fatal("unexplained domain movement accepted")
				}
			})
		}
	}
}
func TestCompleteMVPProgressOrdinaryBudgetAndEarlyRetries(t *testing.T) {
	p := completeMVPSenderProgress{}
	empty := completeRetryEvent(agentloop.Retryable, 0, 0, "", "")
	empty.Metadata.RetriedPending = true
	if ready, category := p.record(empty, true); ready || category != "" || p != (completeMVPSenderProgress{}) {
		t.Fatal("early retry rejected or reset")
	}
	early := completeRetryEvent(agentloop.Retryable, 1, 0, "pending_retained", "")
	if ready, category := p.record(early, true); ready || category != "" {
		t.Fatal("early system capture failure rejected")
	}
	budget := completeRetryEvent(agentloop.Success, 2, 1, "acknowledged", "pending_retained")
	if ready, category := p.record(budget, true); !ready || category != "" {
		t.Fatal("ordinary bounded package progress rejected")
	}
	complete := completeRetryEvent(agentloop.Success, 3, 2, "acknowledged", "acknowledged")
	if ready, category := p.record(complete, true); !ready || category != "" {
		t.Fatal("ordinary package completion rejected")
	}
	later := completeRetryEvent(agentloop.Success, 4, 3, "acknowledged", "not_due")
	if ready, category := p.record(later, true); !ready || category != "" {
		t.Fatal("ordinary no-retry cadence rejected")
	}
}
func TestCompleteMVPOptionalEvidenceRequiresAccountedRetryAdvance(t *testing.T) {
	first, _ := completeMVPEndpointFixture(t, 1)
	third, system := completeMVPEndpointFixture(t, 3)
	if completeMVPEndpointAdvanced(first, third, 3) != nil || completeMVPEndpointAdvanced(first, third, 2) == nil {
		t.Fatal("endpoint advance did not require accounted system sequence")
	}
	retained, _ := completeMVPEndpointFixture(t, 1)
	retained.ServerNow = third.ServerNow
	if completeMVPEndpointRetained(first, retained, system, 3) != nil || completeMVPEndpointRetained(first, retained, system, 2) == nil {
		t.Fatal("retained endpoint did not require accounted system sequence")
	}
	before, _, _ := completeMVPOverviewFixture(t)
	after, _, _ := completeMVPOverviewFixture(t)
	after.ServerNow = after.ServerNow.Add(time.Second)
	if completeMVPOverviewRetainedEvidence(before, after, 1, 3, before.ServerNow, after.ServerNow, "restart", 3) != nil || completeMVPOverviewRetainedEvidence(before, after, 1, 3, before.ServerNow, after.ServerNow, "restart", 2) == nil {
		t.Fatal("retained overview did not require accounted metric sequence")
	}
}

func TestCompleteMVPWaitRetryCannotReplaceSuccessOrTerminalFailure(t *testing.T) {
	t.Run("retry deadline", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		events := make(chan agentloop.Event)
		p := completeMVPSenderProgress{}
		if ready, category := p.record(completeRetryEvent(agentloop.Retryable, 1, 0, "", ""), true); ready || category != "" {
			t.Fatal("retry setup failed")
		}
		cancel()
		got, category := completeMVPWait(ctx, events, &p)
		if got != (agentloop.Event{}) || category != "complete native report deadline" || p.metrics.sequence != 1 || !p.metrics.pending {
			t.Fatal("retry was counted as success or escaped original deadline")
		}
	})
	t.Run("terminal before success", func(t *testing.T) {
		events := make(chan agentloop.Event, 3)
		events <- completeRetryEvent(agentloop.Retryable, 1, 0, "", "")
		events <- completeRetryEvent(agentloop.State, 1, 0, "", "")
		good := completeRetryEvent(agentloop.Success, 1, 1, "acknowledged", "acknowledged")
		good.Metadata.RetriedPending = true
		events <- good
		p := completeMVPSenderProgress{}
		got, category := completeMVPWait(context.Background(), events, &p)
		if got != (agentloop.Event{}) || category != "complete_native_outcome_state" || len(events) != 1 || !p.metrics.pending {
			t.Fatal("terminal event was ignored while waiting for success")
		}
	})
}
func TestCompleteMVPProgressMultiplePackageRetries(t *testing.T) {
	p := completeMVPSenderProgress{}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		event := completeRetryEvent(agentloop.Retryable, sequence, sequence, "acknowledged", "pending_retained")
		if sequence == 3 {
			event.Outcome = agentloop.Success
			event.Metadata.InventoryStatus = "acknowledged"
		}
		if ready, category := p.record(event, true); ready != (sequence == 3) || category != "" {
			t.Fatal("multiple package retries were miscounted")
		}
	}
	if p.counters() != [3]uint64{3, 3, 1} {
		t.Fatal("package retry recaptured or reset independent domains")
	}
}

func TestCompleteMVPProgressRejectsImpossibleEarlyRetryMetadata(t *testing.T) {
	cases := []agentloop.Event{
		completeRetryEvent(agentloop.Retryable, 1, 1, "acknowledged", ""),
		completeRetryEvent(agentloop.Retryable, 0, 0, "", ""),
		completeRetryEvent(agentloop.Retryable, 0, 0, "", ""),
		completeRetryEvent(agentloop.Retryable, 0, 0, "", ""),
	}
	cases[1].Metadata.Duplicate = true
	cases[2].Metadata.AvailablePercentageFields = 1
	cases[3].Metadata.UnavailablePercentageFields = 1
	for _, e := range cases {
		p := completeMVPSenderProgress{}
		if ready, category := p.record(e, true); ready || category != "complete_native_retry_metadata_invalid" || p != (completeMVPSenderProgress{}) {
			t.Fatal("impossible early retry accepted")
		}
	}
}
