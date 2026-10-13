// Package main is a manual, default-off evidence probe, not a product CLI.
// Run only projects injected snapshots. main is the sole native admission edge.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"localrmm/internal/macosinventory"
)

const (
	EvidenceSchema = "tracebolt.macos-native-inventory-evidence.v1"
	MaxReportBytes = 64 * 1024
)

// Provider admits no command, path, arguments, identity, or grant supplied by a
// caller. Test providers use only inert fixtures and the production parser seam.
type Provider func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error)

type Limits struct {
	CommandMilliseconds    int `json:"commandMilliseconds"`
	PipeWaitMilliseconds   int `json:"pipeWaitMilliseconds"`
	ProviderMilliseconds   int `json:"providerMilliseconds"`
	CollectionMilliseconds int `json:"collectionMilliseconds"`
	SnapshotMaxBytes       int `json:"snapshotMaxBytes"`
	ReportMaxBytes         int `json:"reportMaxBytes"`
}

type SourceResult struct {
	ID                 string `json:"id"`
	Availability       string `json:"availability"`
	Reason             string `json:"reason"`
	ParserPassed       bool   `json:"parserPassed"`
	ValidationPassed   bool   `json:"validationPassed"`
	Passed             bool   `json:"passed"`
	Rows               *int   `json:"rows"`
	Addresses          *int   `json:"addresses"`
	MaxOutputBytes     int    `json:"maxOutputBytes"`
	MaxRows            int    `json:"maxRows"`
	MaxAddressesPerRow int    `json:"maxAddressesPerRow"`
	// The unchanged product collector does not expose these measurements.
	// Null is unavailable, never zero or an asserted successful reap.
	StdoutBytes         *int64 `json:"stdoutBytes"`
	StderrBytes         *int64 `json:"stderrBytes"`
	ElapsedMilliseconds *int64 `json:"elapsedMilliseconds"`
	ExitCode            *int   `json:"exitCode"`
	ChildStarted        *bool  `json:"childStarted"`
	ChildReaped         *bool  `json:"childReaped"`
}

type Report struct {
	SchemaVersion                 string          `json:"schemaVersion"`
	Gate                          string          `json:"gate"`
	Mode                          string          `json:"mode"`
	Status                        string          `json:"status"`
	Reason                        string          `json:"reason"`
	Collector                     string          `json:"collector"`
	SnapshotSchema                string          `json:"snapshotSchema"`
	CollectionCalls               int             `json:"collectionCalls"`
	CollectionReturned            bool            `json:"collectionReturned"`
	CollectionElapsedMilliseconds *int64          `json:"collectionElapsedMilliseconds"`
	SnapshotValidated             bool            `json:"snapshotValidated"`
	SnapshotRoundTripValidated    bool            `json:"snapshotRoundTripValidated"`
	SnapshotBytes                 *int            `json:"snapshotBytes"`
	SourcesObserved               int             `json:"sourcesObserved"`
	CommandMetricsAvailable       bool            `json:"commandMetricsAvailable"`
	Limits                        Limits          `json:"limits"`
	Sources                       [5]SourceResult `json:"sources"`
}

func emptyReport(mode, status, reason string) Report {
	r := Report{
		SchemaVersion: EvidenceSchema, Gate: "A", Mode: mode, Status: status, Reason: reason,
		Collector: "macosinventory.CollectNative", SnapshotSchema: macosinventory.SchemaVersion,
		Limits: Limits{int(macosinventory.CommandBudget / time.Millisecond), 200,
			int(macosinventory.ProviderBudget / time.Millisecond),
			int(macosinventory.CollectionBudget / time.Millisecond), macosinventory.MaxBytes, MaxReportBytes},
	}
	ids := [5]string{"hardware_sysctl_v1", "receipts_pkgutil_v1", "processes_ps_ucomm_v1", "interfaces_ipv4_ifconfig_v1", "interfaces_ipv6_ifconfig_v1"}
	rows := [5]int{1, macosinventory.MaxReceipts, macosinventory.MaxProcesses, macosinventory.MaxInterfaces, macosinventory.MaxInterfaces}
	for i := range r.Sources {
		r.Sources[i] = SourceResult{ID: ids[i], Availability: "not_run", Reason: "not_run",
			MaxOutputBytes: macosinventory.MaxSourceBytes, MaxRows: rows[i]}
		if i == 0 {
			r.Sources[i].MaxOutputBytes = 4096
		}
		if i >= 3 {
			r.Sources[i].MaxAddressesPerRow = macosinventory.MaxAddresses
		}
	}
	return r
}

// syntheticRequest never persists a consent, binding, generation, or grant.
// These recognizable constants have no connection to a production identity.
func syntheticRequest() macosinventory.Request {
	binding, grant := strings.Repeat("a", 64), strings.Repeat("b", 32)
	return macosinventory.Request{
		Consent: macosinventory.Consent{SchemaVersion: macosinventory.ConsentVersion,
			Scope: macosinventory.Scope, SenderBinding: binding, GrantID: grant, Enabled: true},
		SenderBinding: binding, GenerationID: "sample_" + strings.Repeat("c", 32),
		CollectedAt: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC),
	}
}

func errorReason(err error) string {
	switch {
	case errors.Is(err, macosinventory.ErrDenied):
		return "access_denied"
	case errors.Is(err, macosinventory.ErrUnsupported):
		return "unsupported_platform"
	case errors.Is(err, macosinventory.ErrMetadata), errors.Is(err, macosinventory.ErrInvalid):
		return "invalid_metadata"
	case errors.Is(err, macosinventory.ErrBounds):
		return "bounds_exceeded"
	case errors.Is(err, macosinventory.ErrBudget), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "budget_exhausted"
	default:
		return "source_unavailable"
	}
}

func statusReason(s macosinventory.Status) string {
	// Never return native text, including a provider's claimed reason or source.
	switch s.Reason {
	case "":
		return "none"
	case macosinventory.ErrDenied.Error():
		return "access_denied"
	case macosinventory.ErrUnsupported.Error():
		return "unsupported_platform"
	case macosinventory.ErrMetadata.Error():
		return "invalid_metadata"
	case macosinventory.ErrBounds.Error():
		return "bounds_exceeded"
	case macosinventory.ErrBudget.Error():
		return "budget_exhausted"
	default:
		return "source_unavailable"
	}
}

// projectSource validates one source with the existing wire validator while all
// siblings are canonical unavailable placeholders. This retains valid sibling
// outcomes when another source or the whole snapshot exceeds its wire budget.
func projectSource(index int, s macosinventory.Snapshot, req macosinventory.Request, out *SourceResult) {
	isolated := macosinventory.Empty(req, macosinventory.ErrUnavailable.Error())
	var status macosinventory.Status
	var rows, addresses int
	switch index {
	case 0:
		isolated.Hardware, status, rows = s.Hardware, s.Hardware.Status, 1
	case 1:
		isolated.Receipts, status, rows = s.Receipts, s.Receipts.Status, len(s.Receipts.Identifiers)
	case 2:
		isolated.Processes, status, rows = s.Processes, s.Processes.Status, len(s.Processes.Rows)
	case 3:
		isolated.Network.IPv4, status, rows = s.Network.IPv4, s.Network.IPv4.Status, len(s.Network.IPv4.Rows)
	case 4:
		isolated.Network.IPv6, status, rows = s.Network.IPv6, s.Network.IPv6.Status, len(s.Network.IPv6.Rows)
	}
	if macosinventory.Validate(isolated) != nil {
		out.Availability, out.Reason = "unavailable", "invalid_metadata"
		return
	}
	out.ValidationPassed = true
	out.Availability, out.Reason = status.Quality, statusReason(status)
	if status.Quality != "observed" {
		return
	}
	out.ParserPassed, out.Passed, out.Rows = true, true, &rows
	if index >= 3 {
		family := isolated.Network.IPv4
		if index == 4 {
			family = isolated.Network.IPv6
		}
		for _, row := range family.Rows {
			addresses += len(row.Addresses)
		}
		out.Addresses = &addresses
	}
}

// Run invokes its injected provider exactly once with synthetic in-memory inputs.
// It performs no native reads itself and labels its result inert_fixture. Only
// main's admitted native boundary may select the real provider and native mode.
// A fixture result is never native acceptance or permission to execute a gate.
func Run(ctx context.Context, provide Provider) (result Report) {
	result = emptyReport("inert_fixture", "failed", "collection_failed")
	defer func() {
		if recover() != nil {
			// Panic values can contain captured native data. Discard, never format.
			calls := result.CollectionCalls
			result = emptyReport("inert_fixture", "failed", "provider_panic")
			result.CollectionCalls = calls
		}
	}()
	if ctx == nil || provide == nil {
		result.Reason = "invalid_input"
		return result
	}
	if ctx.Err() != nil {
		result.Reason = "budget_exhausted"
		return result
	}
	req := syntheticRequest()
	started := time.Now()
	result.CollectionCalls = 1
	snapshot, err := provide(ctx, req)
	elapsed := time.Since(started).Milliseconds()
	result.CollectionReturned = true
	result.CollectionElapsedMilliseconds = &elapsed
	if ctx.Err() != nil {
		// Parent cancellation invalidates the whole collection, even if an
		// injected fixture returned a plausible snapshot after cancellation.
		result.Reason = "budget_exhausted"
		return result
	}
	if err != nil {
		result.Reason = errorReason(err)
	}
	// A missing/incorrect envelope cannot be associated with this invocation.
	if snapshot.SchemaVersion != macosinventory.SchemaVersion || snapshot.Scope != macosinventory.Scope ||
		snapshot.GrantID != req.Consent.GrantID || snapshot.GenerationID != req.GenerationID ||
		snapshot.CollectedAt != req.CollectedAt {
		if err == nil {
			result.Reason = "snapshot_invalid"
		}
		return result
	}
	for i := range result.Sources {
		projectSource(i, snapshot, req, &result.Sources[i])
		if result.Sources[i].Passed {
			result.SourcesObserved++
		}
	}
	result.SnapshotValidated = macosinventory.Validate(snapshot) == nil
	if result.SnapshotValidated {
		encoded, encodeErr := macosinventory.Encode(snapshot)
		if encodeErr == nil {
			n := len(encoded)
			result.SnapshotBytes = &n
			decoded, decodeErr := macosinventory.Decode(encoded)
			result.SnapshotRoundTripValidated = decodeErr == nil && reflect.DeepEqual(decoded, snapshot)
			clear(encoded)
		}
	}
	if err != nil {
		return result
	}
	if !result.SnapshotValidated || !result.SnapshotRoundTripValidated {
		result.Reason = "snapshot_invalid"
		return result
	}
	if result.SourcesObserved != len(result.Sources) {
		result.Reason = "provider_outcome"
		return result
	}
	result.Status, result.Reason = "passed", "none"
	return result
}

// encodeReport accepts only the closed projection, not arbitrary provider data.
func encodeReport(report Report) ([]byte, bool) {
	if !validReport(report) {
		return nil, false
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded)+1 > MaxReportBytes {
		return nil, false
	}
	return append(encoded, '\n'), true
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func validReport(r Report) bool {
	base := emptyReport("", "", "")
	if r.SchemaVersion != base.SchemaVersion || r.Gate != base.Gate || r.Collector != base.Collector ||
		r.SnapshotSchema != base.SnapshotSchema || r.Limits != base.Limits || r.CommandMetricsAvailable ||
		!oneOf(r.Mode, "native", "inert_fixture", "check", "blocked") ||
		!oneOf(r.Status, "passed", "failed", "checked", "blocked") ||
		!oneOf(r.Reason, "none", "not_run", "invalid_input", "unsupported_platform", "host_context_rejected",
			"selector_required", "toolchain_rejected", "provider_panic", "collection_failed", "snapshot_invalid",
			"provider_outcome", "access_denied", "source_unavailable", "invalid_metadata", "bounds_exceeded", "budget_exhausted") ||
		r.CollectionCalls < 0 || r.CollectionCalls > 1 || r.SourcesObserved < 0 || r.SourcesObserved > 5 ||
		(r.CollectionReturned && r.CollectionCalls != 1) ||
		(r.CollectionElapsedMilliseconds != nil && (*r.CollectionElapsedMilliseconds < 0 || *r.CollectionElapsedMilliseconds > 120000)) ||
		(r.SnapshotBytes != nil && (*r.SnapshotBytes <= 0 || *r.SnapshotBytes > macosinventory.MaxBytes)) {
		return false
	}
	observed := 0
	for i, s := range r.Sources {
		b := base.Sources[i]
		if s.ID != b.ID || s.MaxOutputBytes != b.MaxOutputBytes || s.MaxRows != b.MaxRows ||
			s.MaxAddressesPerRow != b.MaxAddressesPerRow || s.StdoutBytes != nil || s.StderrBytes != nil ||
			s.ElapsedMilliseconds != nil || s.ExitCode != nil || s.ChildStarted != nil || s.ChildReaped != nil ||
			!oneOf(s.Availability, "not_run", "observed", "denied", "unavailable") ||
			!oneOf(s.Reason, "none", "not_run", "access_denied", "source_unavailable", "unsupported_platform",
				"invalid_metadata", "bounds_exceeded", "budget_exhausted") {
			return false
		}
		if s.Availability == "observed" {
			if !s.ParserPassed || !s.ValidationPassed || !s.Passed || s.Reason != "none" ||
				s.Rows == nil || *s.Rows < 0 || *s.Rows > s.MaxRows || (i != 1 && *s.Rows == 0) {
				return false
			}
			if i < 3 && s.Addresses != nil || i >= 3 && (s.Addresses == nil || *s.Addresses < 0 || *s.Addresses > *s.Rows*macosinventory.MaxAddresses) {
				return false
			}
			observed++
		} else if s.Passed || s.ParserPassed || s.Rows != nil || s.Addresses != nil || s.Reason == "none" {
			return false
		}
		if s.Availability == "not_run" && (s.ValidationPassed || s.Reason != "not_run") ||
			s.Availability == "denied" && (!s.ValidationPassed || s.Reason != "access_denied") ||
			s.Availability == "unavailable" && !oneOf(s.Reason, "source_unavailable", "unsupported_platform", "invalid_metadata", "bounds_exceeded", "budget_exhausted") {
			return false
		}
	}
	if observed != r.SourcesObserved || (r.CollectionReturned != (r.CollectionElapsedMilliseconds != nil)) ||
		(r.SnapshotRoundTripValidated && !r.SnapshotValidated) || (r.SnapshotBytes != nil && !r.SnapshotValidated) ||
		(r.SnapshotValidated && r.SnapshotBytes == nil) {
		return false
	}
	if r.Mode == "check" || r.Mode == "blocked" {
		return r.CollectionCalls == 0 && !r.CollectionReturned && !r.SnapshotValidated && r.SourcesObserved == 0 &&
			((r.Mode == "check" && r.Status == "checked" && r.Reason == "not_run") || (r.Mode == "blocked" && r.Status == "blocked"))
	}
	return oneOf(r.Status, "passed", "failed") && (r.Status != "passed" ||
		(r.CollectionCalls == 1 && r.CollectionReturned && r.SnapshotValidated && r.SnapshotRoundTripValidated && r.SourcesObserved == 5 && r.Reason == "none"))
}
