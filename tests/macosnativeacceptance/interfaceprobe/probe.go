package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"localrmm/internal/macosinventory"
)

const EvidenceSchema = "tracebolt.macos-native-interface-diagnostics.v1"
const MaxReportBytes = 16 * 1024

// Command accepts a closed family selector only. Native bytes stay in memory.
type Command func(context.Context, bool) ([]byte, error)

type Limits struct {
	CommandMilliseconds      int `json:"commandMilliseconds"`
	PipeWaitMilliseconds     int `json:"pipeWaitMilliseconds"`
	MaxOutputBytes           int `json:"maxOutputBytes"`
	MaxInterfaces            int `json:"maxInterfaces"`
	MaxAddressesPerInterface int `json:"maxAddressesPerInterface"`
	ReportMaxBytes           int `json:"reportMaxBytes"`
}

type Family struct {
	ID             string `json:"id"`
	CommandCalls   int    `json:"commandCalls"`
	CommandOutcome string `json:"commandOutcome"`
	ParserCalls    int    `json:"parserCalls"`
	ParserCode     string `json:"parserCode"`
	Validation     string `json:"validation"`
	Passed         bool   `json:"passed"`
	// The unchanged command runner exposes none of these observations.
	// Null is unavailable, never evidence of zero bytes or successful child reap.
	StdoutBytes         *int64 `json:"stdoutBytes"`
	StderrBytes         *int64 `json:"stderrBytes"`
	ElapsedMilliseconds *int64 `json:"elapsedMilliseconds"`
	ExitCode            *int   `json:"exitCode"`
	ChildStarted        *bool  `json:"childStarted"`
	ChildReaped         *bool  `json:"childReaped"`
}

type Report struct {
	SchemaVersion           string    `json:"schemaVersion"`
	Gate                    string    `json:"gate"`
	Mode                    string    `json:"mode"`
	Status                  string    `json:"status"`
	Reason                  string    `json:"reason"`
	CommandMetricsAvailable bool      `json:"commandMetricsAvailable"`
	Limits                  Limits    `json:"limits"`
	Families                [2]Family `json:"families"`
}

func emptyReport(mode, status, reason string) Report {
	r := Report{SchemaVersion: EvidenceSchema, Gate: "I", Mode: mode, Status: status, Reason: reason,
		Limits: Limits{int(macosinventory.CommandBudget / time.Millisecond), 200, macosinventory.MaxSourceBytes, macosinventory.MaxInterfaces, macosinventory.MaxAddresses, MaxReportBytes}}
	for i, id := range []string{"interfaces_ipv4_ifconfig_v1", "interfaces_ipv6_ifconfig_v1"} {
		r.Families[i] = Family{ID: id, CommandOutcome: "not_run", ParserCode: "not_run", Validation: "not_run"}
	}
	return r
}

func commandOutcome(err error) string {
	switch {
	case err == nil:
		return "succeeded"
	case errors.Is(err, macosinventory.ErrDenied):
		return "access_denied"
	case errors.Is(err, macosinventory.ErrUnsupported):
		return "unsupported_platform"
	case errors.Is(err, macosinventory.ErrBounds):
		return "bounds_exceeded"
	case errors.Is(err, macosinventory.ErrBudget), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "budget_exhausted"
	default:
		return "source_unavailable"
	}
}

func callCommand(ctx context.Context, ipv6 bool, command Command) (raw []byte, outcome string) {
	defer func() {
		if recover() != nil {
			raw, outcome = nil, "command_panic"
		}
	}()
	var err error
	raw, err = command(ctx, ipv6)
	outcome = commandOutcome(err)
	return
}

func validateFamily(v macosinventory.Interfaces, ipv6 bool) bool {
	// A fixed synthetic envelope admits only this family. No collection, grant,
	// identity, state, serialization of values or sibling observation occurs.
	req := macosinventory.Request{Consent: macosinventory.Consent{GrantID: strings.Repeat("b", 32)},
		GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)}
	s := macosinventory.Empty(req, macosinventory.ErrUnavailable.Error())
	if ipv6 {
		s.Network.IPv6 = v
	} else {
		s.Network.IPv4 = v
	}
	return macosinventory.Validate(s) == nil
}

func runFamily(ctx context.Context, ipv6 bool, command Command, r *Family) {
	r.CommandCalls = 1
	raw, outcome := callCommand(ctx, ipv6, command)
	defer clear(raw)
	r.CommandOutcome = outcome
	if ctx.Err() != nil {
		r.CommandOutcome = "budget_exhausted"
	}
	if r.CommandOutcome != "succeeded" {
		return
	}
	r.ParserCalls = 1
	// Exactly one parser invocation, before any canonical failure substitution.
	value, code, err := macosinventory.ParseInterfacesWithDiagnostic(raw, ipv6)
	r.ParserCode = code.String()
	if err != nil {
		return
	}
	r.Validation = "failed"
	if validateFamily(value, ipv6) {
		r.Validation, r.Passed = "passed", true
	}
}

// Run projects two isolated, once-only family attempts. An ordinary failure
// never erases or suppresses its sibling. Cancellation never starts a new child.
// The native runner supplies its unchanged one-second command/200-ms pipe bound.
func Run(ctx context.Context, command Command) Report {
	r := emptyReport("inert_fixture", "failed", "interface_outcome")
	if ctx == nil || command == nil {
		r.Reason = "invalid_input"
		return r
	}
	for i := range r.Families {
		if ctx.Err() != nil {
			r.Reason = "budget_exhausted"
			return r
		}
		runFamily(ctx, i == 1, command, &r.Families[i])
	}
	if ctx.Err() != nil {
		r.Reason = "budget_exhausted"
		return r
	}
	if r.Families[0].Passed && r.Families[1].Passed {
		r.Status, r.Reason = "passed", "none"
	}
	return r
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func validParserCode(s string) bool {
	return oneOf(s, "none", "source_size", "source_control", "source_newline", "source_line_size", "source_encoding",
		"empty_record", "orphan_record", "blank_record", "interface_limit", "header_shape", "header_flags", "header_name",
		"mtu_missing", "mtu_duplicate", "mtu_value", "address_shape", "address_numeric", "address_family", "address_zone",
		"prefix_missing", "prefix_duplicate", "prefix_value", "address_limit", "result_empty", "duplicate_interface", "duplicate_address", "result_invalid")
}

func validReport(r Report) bool {
	base := emptyReport("", "", "")
	if r.SchemaVersion != base.SchemaVersion || r.Gate != "I" || r.Limits != base.Limits || r.CommandMetricsAvailable ||
		!oneOf(r.Mode, "native", "inert_fixture", "check", "blocked") {
		return false
	}
	allPassed, calls := true, 0
	for i, f := range r.Families {
		if f.ID != base.Families[i].ID || f.CommandCalls < 0 || f.CommandCalls > 1 || f.ParserCalls < 0 || f.ParserCalls > 1 ||
			f.StdoutBytes != nil || f.StderrBytes != nil || f.ElapsedMilliseconds != nil || f.ExitCode != nil || f.ChildStarted != nil || f.ChildReaped != nil {
			return false
		}
		calls += f.CommandCalls
		allPassed = allPassed && f.Passed
		if f.CommandCalls == 0 {
			if f != base.Families[i] {
				return false
			}
		} else if f.CommandOutcome != "succeeded" {
			if !oneOf(f.CommandOutcome, "access_denied", "source_unavailable", "unsupported_platform", "bounds_exceeded", "budget_exhausted", "command_panic") ||
				f.ParserCalls != 0 || f.ParserCode != "not_run" || f.Validation != "not_run" || f.Passed {
				return false
			}
		} else {
			if f.ParserCalls != 1 || !validParserCode(f.ParserCode) {
				return false
			}
			if f.ParserCode == "none" {
				if !oneOf(f.Validation, "passed", "failed") || f.Passed != (f.Validation == "passed") {
					return false
				}
			} else if f.Validation != "not_run" || f.Passed {
				return false
			}
		}
	}
	if r.Mode == "check" {
		return r.Status == "checked" && r.Reason == "not_run" && calls == 0
	}
	if r.Mode == "blocked" {
		return r.Status == "blocked" && calls == 0 && oneOf(r.Reason, "selector_required", "unsupported_platform", "diagnostic_build_required", "toolchain_rejected", "host_context_rejected")
	}
	if r.Status == "passed" {
		return allPassed && r.Reason == "none"
	}
	if r.Status != "failed" {
		return false
	}
	switch r.Reason {
	case "invalid_input":
		return calls == 0
	case "budget_exhausted":
		return true
	case "interface_outcome":
		return calls == 2 && !allPassed
	default:
		return false
	}
}

func encodeReport(r Report) ([]byte, bool) {
	if !validReport(r) {
		return nil, false
	}
	b, err := json.Marshal(r)
	if err != nil || len(b)+1 > MaxReportBytes {
		return nil, false
	}
	return append(b, '\n'), true
}
