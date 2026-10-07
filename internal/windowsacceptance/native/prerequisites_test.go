package native

import "testing"

func TestPrerequisiteObservationClassifiesPolicyNotActualTokenAccess(t *testing.T) {
	cases := []struct {
		check        string
		reason       Reason
		err          error
		status, want string
	}{
		{"complete", ReasonNone, nil, "supported", "none"},
		{"ancestor-policy", ReasonPrerequisite, ErrAcceptance, "blocked", "prerequisite-blocked"},
		{"resource-absence", ReasonExisting, ErrAcceptance, "blocked", "existing-resource"},
		{"platform", ReasonUnsupported, ErrAcceptance, "unverified", "unsupported-platform"},
		{"filesystem", ReasonTimeout, ErrAcceptance, "unverified", "cancelled"},
		{"complete", ReasonOperation, ErrAcceptance, "unverified", "inspection-failed"},
		{"private-native-error", ReasonOperation, ErrAcceptance, "unverified", "inspection-failed"},
	}
	for _, c := range cases {
		p := prerequisiteObservation(c.check, c.reason, c.err)
		if !p.Valid() || p.Status != c.status || p.Reason != c.want {
			t.Fatal("invalid finite prerequisite classification")
		}
	}
}
func TestPrerequisiteObservationRejectsFalseNativeOrSuccessReasons(t *testing.T) {
	for _, p := range []PrerequisiteObservation{{"supported", "ancestor-policy", "none"}, {"supported", "complete", "prerequisite-blocked"}, {"blocked", "complete", "prerequisite-blocked"}, {"blocked", "elevation", "existing-resource"}, {"unverified", "complete", "unsupported-platform"}, {"native_pass", "complete", "none"}, {"unverified", "platform", "private-error"}} {
		if p.Valid() {
			t.Fatal("overstated prerequisite observation")
		}
	}
}
