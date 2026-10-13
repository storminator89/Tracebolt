package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/macosinventory"
)

const fixture4 = "privacycanary: flags=41<UP,RUNNING> mtu 1499\n\tinet 192.0.2.197 netmask 0xffffff00\n"
const fixture6 = "privacycanary: flags=41<UP,RUNNING> mtu 1499\n\tinet6 2001:db8::197 prefixlen 64\n"

func goodCommand(_ context.Context, ipv6 bool) ([]byte, error) {
	if ipv6 {
		return []byte(fixture6), nil
	}
	return []byte(fixture4), nil
}

func assertReport(t *testing.T, r Report) []byte {
	t.Helper()
	b, ok := encodeReport(r)
	if !ok || len(b) > MaxReportBytes {
		t.Fatalf("invalid projection: %#v", r)
	}
	for _, secret := range []string{"privacycanary", "1499", "192.0.2.197", "2001:db8::197", "raw-error-canary", "panic-canary"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("privacy leak: %q", secret)
		}
	}
	return b
}

func TestExactlyTwoCommandsAndOneParserPerSuccessfulCommand(t *testing.T) {
	var calls []bool
	var rawBuffers [][]byte
	r := Run(context.Background(), func(ctx context.Context, ipv6 bool) ([]byte, error) {
		calls = append(calls, ipv6)
		b, e := goodCommand(ctx, ipv6)
		rawBuffers = append(rawBuffers, b)
		return b, e
	})
	if !reflect.DeepEqual(calls, []bool{false, true}) || r.Status != "passed" {
		t.Fatal("wrong calls or result")
	}
	for _, f := range r.Families {
		if f.CommandCalls != 1 || f.CommandOutcome != "succeeded" || f.ParserCalls != 1 || f.ParserCode != "none" || f.Validation != "passed" || !f.Passed {
			t.Fatal("wrong family")
		}
	}
	for _, b := range rawBuffers {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("raw buffer retained")
		}
	}
	assertReport(t, r)
}

func TestSiblingFailuresAreIndependentAndClosed(t *testing.T) {
	for _, firstFails := range []bool{false, true} {
		for _, failure := range []string{"parse", "denied", "unavailable", "panic", "bounds", "budget", "unsupported"} {
			t.Run(failure+map[bool]string{false: "_second", true: "_first"}[firstFails], func(t *testing.T) {
				calls := 0
				r := Run(context.Background(), func(ctx context.Context, ipv6 bool) ([]byte, error) {
					calls++
					if ipv6 == firstFails {
						return goodCommand(ctx, ipv6)
					}
					switch failure {
					case "parse":
						return []byte("privacycanary: flags=41<UP,RUNNING> metric 7\n"), nil
					case "denied":
						return []byte("raw-error-canary"), macosinventory.ErrDenied
					case "bounds":
						return nil, macosinventory.ErrBounds
					case "budget":
						return nil, macosinventory.ErrBudget
					case "unsupported":
						return nil, macosinventory.ErrUnsupported
					case "panic":
						panic("panic-canary")
					default:
						return nil, errors.New("raw-error-canary")
					}
				})
				failed, good := 1, 0
				if firstFails {
					failed, good = 0, 1
				}
				if calls != 2 || r.Status != "failed" || r.Reason != "interface_outcome" || !r.Families[good].Passed || r.Families[failed].Passed {
					t.Fatal("sibling truth lost")
				}
				f := r.Families[failed]
				if failure == "parse" {
					if f.ParserCalls != 1 || f.ParserCode != "mtu_missing" || f.Validation != "not_run" {
						t.Fatal("missing diagnostic")
					}
				} else if f.ParserCalls != 0 || f.ParserCode != "not_run" {
					t.Fatal("parsed command failure")
				}
				assertReport(t, r)
			})
		}
	}
}

func TestCancellationStopsNewAttemptsAndPreservesEarlierFamily(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	r := Run(ctx, func(context.Context, bool) ([]byte, error) { calls++; return nil, nil })
	if calls != 0 || r.Reason != "budget_exhausted" {
		t.Fatal("pre-cancel invoked command")
	}
	assertReport(t, r)
	ctx, cancel = context.WithCancel(context.Background())
	r = Run(ctx, func(ctx context.Context, ipv6 bool) ([]byte, error) { calls++; cancel(); return goodCommand(ctx, ipv6) })
	if calls != 1 || r.Families[0].CommandOutcome != "budget_exhausted" || r.Families[0].ParserCalls != 0 || r.Families[1].CommandCalls != 0 {
		t.Fatal("cancellation accepted data or retried")
	}
	assertReport(t, r)
	ctx, cancel = context.WithCancel(context.Background())
	r = Run(ctx, func(ctx context.Context, ipv6 bool) ([]byte, error) {
		if ipv6 {
			cancel()
		}
		return goodCommand(ctx, ipv6)
	})
	if !r.Families[0].Passed || r.Families[1].Passed || r.Reason != "budget_exhausted" {
		t.Fatal("lost completed sibling")
	}
	assertReport(t, r)
}

type lateCancellation struct {
	context.Context
	checks int
}

func (c *lateCancellation) Err() error {
	c.checks++
	if c.checks == 5 {
		return context.Canceled
	}
	return nil
}

func TestLateCancellationFailsOverallWithoutErasingCompletedFamilies(t *testing.T) {
	ctx := &lateCancellation{Context: context.Background()}
	r := Run(ctx, goodCommand)
	if r.Status != "failed" || r.Reason != "budget_exhausted" || !r.Families[0].Passed || !r.Families[1].Passed {
		t.Fatal("late cancellation lost truth")
	}
	assertReport(t, r)
}

func TestInvalidInputsAndParserBounds(t *testing.T) {
	assertReport(t, Run(nil, goodCommand))
	assertReport(t, Run(context.Background(), nil))
	for _, test := range []struct{ raw, code string }{
		{strings.Repeat("x", macosinventory.MaxSourceBytes+1), "source_size"},
		{strings.Repeat("x", 4097) + "\n", "source_line_size"},
		{"", "result_empty"}, {"privacycanary", "source_newline"},
		{"privacycanary\x00\n", "source_control"},
	} {
		r := Run(context.Background(), func(context.Context, bool) ([]byte, error) { return []byte(test.raw), nil })
		for _, f := range r.Families {
			if f.ParserCalls != 1 || f.ParserCode != test.code || f.Passed {
				t.Fatalf("wrong code: %s wanted %s", f.ParserCode, test.code)
			}
		}
		assertReport(t, r)
	}
}

func TestValidatorRejectsUnknownCodesInconsistentStatesAndMetrics(t *testing.T) {
	base := Run(context.Background(), goodCommand)
	mutations := []func(*Report){
		func(r *Report) { r.SchemaVersion = "unknown" }, func(r *Report) { r.Reason = "raw-error-canary" },
		func(r *Report) { r.Gate = "A" }, func(r *Report) { r.CommandMetricsAvailable = true },
		func(r *Report) { r.Limits.CommandMilliseconds = 1001 }, func(r *Report) { r.Limits.PipeWaitMilliseconds = 201 },
		func(r *Report) { r.Families[0].ParserCode = "unclassified" }, func(r *Report) { r.Families[0].CommandCalls = 2 },
		func(r *Report) { r.Families[0].ParserCalls = 2 }, func(r *Report) { r.Families[0].ID = "privacycanary" },
		func(r *Report) { r.Families[0].StdoutBytes = new(int64) }, func(r *Report) { r.Families[0].StderrBytes = new(int64) },
		func(r *Report) { r.Families[0].ElapsedMilliseconds = new(int64) }, func(r *Report) { r.Families[0].ExitCode = new(int) },
		func(r *Report) { r.Families[0].ChildStarted = new(bool) }, func(r *Report) { r.Families[0].ChildReaped = new(bool) },
		func(r *Report) { r.Families[0].Validation = "not_run" }, func(r *Report) { r.Families[0].CommandOutcome = "not_run" },
		func(r *Report) { r.Families[0].ParserCode = "mtu_missing" }, func(r *Report) { r.Families[0].Passed = false },
		func(r *Report) { r.Status = "failed"; r.Reason = "none" }, func(r *Report) { r.Mode = "check" },
	}
	for i, mutate := range mutations {
		r := base
		mutate(&r)
		if _, ok := encodeReport(r); ok {
			t.Fatalf("accepted mutation %d", i)
		}
	}
}

func TestProjectionHasOnlyClosedKnownFields(t *testing.T) {
	b := assertReport(t, Run(context.Background(), goodCommand))
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v) != 8 {
		t.Fatal("unexpected report fields")
	}
	for _, item := range v["families"].([]any) {
		if len(item.(map[string]any)) != 13 {
			t.Fatal("unexpected family fields")
		}
	}
	for _, code := range []string{"unclassified", "not_run", "privacycanary"} {
		if validParserCode(code) {
			t.Fatal("unknown parser code accepted")
		}
	}
}

func TestCanonicalValidationRejectsForgedParsedValues(t *testing.T) {
	v, _, err := macosinventory.ParseInterfacesWithDiagnostic([]byte(fixture4), false)
	if err != nil || !validateFamily(v, false) {
		t.Fatal("fixture")
	}
	v.Rows[0].Name = "invalid/name"
	if validateFamily(v, false) {
		t.Fatal("canonical validator bypassed")
	}
}
