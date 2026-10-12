package currentsetupgate

import (
	"localrmm/internal/windowsacceptance/setupgate"
	"testing"
)

func TestInitialChooserStagesAreFiniteFailureOnlyAcrossCurrentCases(t *testing.T) {
	_, b, _ := authorized()
	for _, which := range Cases {
		b.Case = which
		for _, stage := range setupgate.InitialChooserFailureStages {
			r := NewReport(b)
			r.Status, r.Stage, r.Reason = "failed", stage, "operation_failed"
			r.ApprovalValidated, r.NativeActionsAttempted, r.PlatformDisposalRequired = true, true, true
			if r.Validate() != nil {
				t.Fatalf("finite failure rejected: %s/%s", which, stage)
			}
			for _, suffix := range []string{"-private", "\n", " "} {
				bad := r
				bad.Stage += suffix
				if bad.Validate() == nil {
					t.Fatal("unbounded stage admitted")
				}
			}
			blocked := NewReport(b)
			blocked.Stage = stage
			if blocked.Validate() == nil {
				t.Fatal("failure label admitted as blocked")
			}
			r.Status = "passed_packaged_gui_subset"
			for check := range r.Checks {
				r.Checks[check] = true
			}
			if r.Validate() == nil {
				t.Fatal("failure label admitted as success")
			}
		}
	}
}
