package setupgate

// GUISequence uses the same ordered callbacks as the native driver. Only fixed
// labels cross the report boundary; callback errors and UI text never do.
type PreflightSteps struct {
	Launch, Choose, Consent, Cancel, Exit, Service, ProgramFiles, ProgramData func() error
}

func CheckPreflight(stage func(string), s PreflightSteps) error {
	if stage == nil {
		return ErrGuard
	}
	for _, step := range []struct {
		label string
		run   func() error
	}{
		{"preflight-launch", s.Launch}, {"preflight-choose", s.Choose},
		{"preflight-consent", s.Consent}, {"preflight-cancel-click", s.Cancel},
		{"preflight-exit", s.Exit}, {"preflight-fresh-service", s.Service}, {"preflight-fresh-program-files", s.ProgramFiles}, {"preflight-fresh-program-data", s.ProgramData},
	} {
		stage(step.label)
		if step.run == nil || step.run() != nil {
			return ErrGuard
		}
	}
	return nil
}

type ConsentSteps struct {
	Next, WaitReview, Back, WaitInput, WaitEnabled func() error
	NextEnabled                                    func() bool
	Present                                        func(int) bool
	Unchecked, ClickChecked                        func(int) error
}

// CheckConsent preserves two full acknowledgement passes and the intervening
// Back/Next reset. Checking a later control never excuses a failed earlier one.
func CheckConsent(stage func(string), http bool, s ConsentSteps) error {
	if stage == nil || s.Next == nil || s.WaitReview == nil || s.Back == nil || s.WaitInput == nil || s.WaitEnabled == nil || s.NextEnabled == nil || s.Present == nil || s.Unchecked == nil || s.ClickChecked == nil {
		return ErrGuard
	}
	stage("consent-open")
	if s.Next() != nil {
		return ErrGuard
	}
	stage("consent-review")
	if s.WaitReview() != nil {
		return ErrGuard
	}
	ids := []int{104, 105, 106, 107}
	if http {
		ids = append(ids, 108)
	} else {
		stage("consent-http-absent")
		if s.Present(108) {
			return ErrGuard
		}
	}
	labels := [][]string{
		{"consent-first-disabled", "consent-first-reset", "consent-first-scope", "consent-first-service", "consent-first-identity", "consent-first-compared", "consent-first-http", "consent-first-enabled"},
		{"consent-second-disabled", "consent-second-reset", "consent-second-scope", "consent-second-service", "consent-second-identity", "consent-second-compared", "consent-second-http", "consent-second-enabled"},
	}
	for pass := 0; pass < 2; pass++ {
		stage(labels[pass][0])
		if s.NextEnabled() {
			return ErrGuard
		}
		stage(labels[pass][1])
		for _, id := range ids {
			if id == 108 {
				if pass == 0 {
					stage("consent-first-http-reset")
				} else {
					stage("consent-second-http-reset")
				}
			}
			if s.Unchecked(id) != nil {
				return ErrGuard
			}
		}
		for i, id := range ids {
			stage(labels[pass][2+i])
			if s.ClickChecked(id) != nil {
				return ErrGuard
			}
		}
		stage(labels[pass][7])
		if s.WaitEnabled() != nil {
			return ErrGuard
		}
		if pass == 0 {
			stage("consent-back")
			if s.Back() != nil {
				return ErrGuard
			}
			stage("consent-input")
			if s.WaitInput() != nil {
				return ErrGuard
			}
			stage("consent-reopen")
			if s.Next() != nil {
				return ErrGuard
			}
			stage("consent-review-reset")
			if s.WaitReview() != nil {
				return ErrGuard
			}
		}
	}
	return nil
}
