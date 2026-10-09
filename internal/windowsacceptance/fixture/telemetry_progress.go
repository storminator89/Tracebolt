package fixture

// TelemetryObservation counts only requests admitted after the existing exact
// HTTP request and size checks and under MaxRequests. It says nothing about TCP,
// TLS handshakes, rejected request envelopes, or the endpoint's collection work.
// Fields are cumulative and are updated with the receipt state under its lock.
// Rejection names identify protocol checkpoints, not inferred endpoint causes:
// authorizationRejected includes signed-request verification; unavailable also
// covers an admitted request that reaches the fixed accepted-frame capacity.
type TelemetryObservation struct {
	Admitted              uint64 `json:"admitted"`
	InFlight              uint64 `json:"inFlight"`
	Accepted              uint64 `json:"accepted"`
	Duplicate             uint64 `json:"duplicate"`
	AuthorizationRejected uint64 `json:"authorizationRejected"`
	BodyRejected          uint64 `json:"bodyRejected"`
	FrameRejected         uint64 `json:"frameRejected"`
	ScopeRejected         uint64 `json:"scopeRejected"`
	FreshnessRejected     uint64 `json:"freshnessRejected"`
	Unavailable           uint64 `json:"unavailable"`
}

func (o TelemetryObservation) Validate() error {
	if o.Admitted > MaxRequests || o.InFlight > 2 || o.Accepted > MaxFrames || o.Duplicate > 0 && o.Accepted == 0 {
		return ErrFixture
	}
	var total uint64
	for _, n := range []uint64{o.InFlight, o.Accepted, o.Duplicate, o.AuthorizationRejected, o.BodyRejected, o.FrameRejected, o.ScopeRejected, o.FreshnessRejected, o.Unavailable} {
		if n > MaxRequests {
			return ErrFixture
		}
		total += n // Every summand was bounded before addition.
	}
	if total != o.Admitted {
		return ErrFixture
	}
	return nil
}

type telemetryOutcome uint8

const (
	telemetryAccepted telemetryOutcome = iota
	telemetryDuplicate
	telemetryAuthorizationRejected
	telemetryBodyRejected
	telemetryFrameRejected
	telemetryScopeRejected
	telemetryFreshnessRejected
	telemetryUnavailable
)

// finishTelemetryLocked is called exactly once for an admitted telemetry
// request, while holding the existing receipt/state lock.
func (s *state) finishTelemetryLocked(outcome telemetryOutcome) {
	s.telemetryProgress.InFlight--
	var count *uint64
	switch outcome {
	case telemetryAccepted:
		count = &s.telemetryProgress.Accepted
	case telemetryDuplicate:
		count = &s.telemetryProgress.Duplicate
	case telemetryAuthorizationRejected:
		count = &s.telemetryProgress.AuthorizationRejected
	case telemetryBodyRejected:
		count = &s.telemetryProgress.BodyRejected
	case telemetryFrameRejected:
		count = &s.telemetryProgress.FrameRejected
	case telemetryScopeRejected:
		count = &s.telemetryProgress.ScopeRejected
	case telemetryFreshnessRejected:
		count = &s.telemetryProgress.FreshnessRejected
	default:
		count = &s.telemetryProgress.Unavailable
	}
	*count++
}

func (s *state) finishTelemetry(outcome telemetryOutcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishTelemetryLocked(outcome)
}
