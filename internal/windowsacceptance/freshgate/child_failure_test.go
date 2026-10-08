package freshgate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChildFailureCodesExhaustiveAndFinite(t *testing.T) {
	pairs := ChildFailurePairs()
	seen := map[int]bool{}
	for _, pair := range pairs {
		code := ChildFailureExitCode(pair[0], pair[1])
		if code <= 1 || seen[code] {
			t.Fatalf("ambiguous finite pair %v", pair)
		}
		seen[code] = true
		stage, category := DecodeChildFailureExit(uint32(code))
		if [2]string{stage, category} != pair {
			t.Fatal("code mismatch", pair)
		}
		r := NewReport(strings.Repeat("a", 40))
		r.Status, r.ApprovalValidated, r.NativeActionsAttempted = "failed", true, true
		r.NaturalChildExit, r.ChildFailureStage, r.ChildFailureCategory = "nonzero", stage, category
		raw, err := r.Encode()
		if err != nil {
			t.Fatal("known failure rejected", pair)
		}
		if strings.Contains(string(raw), "exitCode") || strings.Contains(string(raw), "rawError") {
			t.Fatal("raw diagnostic persisted")
		}
		for _, exit := range []string{"zero", "unknown"} {
			r.NaturalChildExit = exit
			if r.Validate() == nil {
				t.Fatal("failure inferred from absent natural failure", pair)
			}
		}
		r.NaturalChildExit, r.Status = "nonzero", "passed_fresh_native_subset"
		if r.Validate() == nil {
			t.Fatal("failure promoted success")
		}
	}
	for _, code := range []uint32{1, 2, 259, 999, 19999, 0xffffffff} {
		if seen[int(code)] {
			continue
		}
		stage, category := DecodeChildFailureExit(code)
		if stage != "unknown" || category != "unknown" {
			t.Fatal("arbitrary code decoded")
		}
	}
	if len(childFailurePairs) >= serviceFailureCodeBase-childFailureCodeBase {
		t.Fatal("code ranges overlap")
	}
	// Cross every finite value, including all impossible combinations.
	stages, categories := map[string]bool{}, map[string]bool{}
	valid := map[[2]string]bool{}
	for _, p := range pairs {
		stages[p[0]], categories[p[1]], valid[p] = true, true, true
	}
	for s := range stages {
		for c := range categories {
			if (ChildFailureExitCode(s, c) != 1) != valid[[2]string{s, c}] {
				t.Fatal("invented pair admitted", s, c)
			}
		}
	}
}

func TestChildFailureReportDefaultsAndStrictValues(t *testing.T) {
	r := NewReport(strings.Repeat("a", 40))
	raw, _ := r.Encode()
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || fields["childFailureStage"] != "unknown" || fields["childFailureCategory"] != "unknown" {
		t.Fatal("missing defaults")
	}
	for _, field := range []string{"childFailureStage", "childFailureCategory"} {
		for _, value := range []any{nil, true, false, 0, 1.5, []any{}, map[string]any{}, "", "private output", "none\n"} {
			copy := passingFreshReport()
			encoded, _ := copy.Encode()
			_ = json.Unmarshal(encoded, &fields)
			fields[field] = value
			encoded, _ = json.Marshal(fields)
			var decoded Report
			if json.Unmarshal(encoded, &decoded) == nil && decoded.Validate() == nil {
				t.Fatal("invalid diagnostic admitted", field)
			}
		}
	}
	for _, exit := range []string{"unknown", "nonzero"} {
		r.Status, r.ApprovalValidated, r.NativeActionsAttempted, r.NaturalChildExit = "failed", true, true, exit
		if r.Validate() != nil {
			t.Fatal("unknown failure evidence rejected")
		}
	}
	r.NaturalChildExit = "zero"
	if r.Validate() == nil {
		t.Fatal("zero exit has unknown failure")
	}
	r.ChildFailureStage, r.ChildFailureCategory = "none", "none"
	if r.Validate() != nil {
		t.Fatal("observed zero rejected")
	}
}
