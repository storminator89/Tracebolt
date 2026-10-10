package setupgate

import "testing"

func TestChooserBranchStagesAreFailureOnlyAcrossCases(t *testing.T) {
	if len(ChooserClickFailureStages) != 32 {
		t.Fatal("finite chooser vocabulary changed")
	}
	for _, which := range Cases {
		_, b, _ := authorized()
		b.Case = which
		for _, stage := range ChooserClickFailureStages {
			r := NewReport(b)
			r.Status, r.Stage, r.Reason = "failed", stage, "operation_failed"
			r.ApprovalValidated, r.NativeActionsAttempted, r.PlatformDisposalRequired = true, true, true
			if err := r.Validate(); err != nil {
				t.Fatal("finite failure rejected")
			}
			for _, status := range []string{"blocked", "passed_packaged_gui_subset"} {
				bad := r
				bad.Status = status
				if bad.Validate() == nil {
					t.Fatal("failure label promoted")
				}
			}
			blocked := NewReport(b)
			blocked.Stage, blocked.Reason = stage, "operation_failed"
			if blocked.Validate() == nil {
				t.Fatal("otherwise valid blocked report admitted diagnostic failure label")
			}
			for _, suffix := range []string{"-private", "\n", " "} {
				bad := r
				bad.Stage += suffix
				if bad.Validate() == nil {
					t.Fatal("unbounded label admitted")
				}
			}
		}
	}
}

func TestRetentionStagesAreNormalCaseFailureOnly(t *testing.T) {
	if len(RetentionFailureStages) != 30 {
		t.Fatal("finite retention vocabulary changed")
	}
	for _, which := range Cases {
		_, b, _ := authorized()
		b.Case = which
		for _, stage := range RetentionFailureStages {
			r := NewReport(b)
			r.Status, r.Stage, r.Reason = "failed", stage, "operation_failed"
			r.ApprovalValidated, r.NativeActionsAttempted, r.PlatformDisposalRequired = true, true, true
			if (r.Validate() == nil) != NormalCase(which) {
				t.Fatal("retention case rule violated")
			}
			blocked := NewReport(b)
			blocked.Stage, blocked.Reason = stage, "operation_failed"
			if blocked.Validate() == nil {
				t.Fatal("blocked retention failure admitted")
			}
			r.Status = "passed_packaged_gui_subset"
			if r.Validate() == nil {
				t.Fatal("retention failure promoted")
			}
		}
	}
}
