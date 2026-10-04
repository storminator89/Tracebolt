// Package agentloop schedules sequential, read-only agent attempts in the
// foreground. It does not collect, send, persist, enroll, or install anything.
package agentloop

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultInterval = 30 * time.Second
	MinInterval     = 15 * time.Second
	MaxInterval     = time.Hour
	MaxBackoff      = 5 * time.Minute
)

var (
	ErrConfiguration = errors.New("agent loop configuration is invalid or unavailable")
	ErrState         = errors.New("agent loop stopped for unavailable or incompatible state")
	ErrRevoked       = errors.New("agent loop stopped for revoked authorization")
	ErrAttempt       = errors.New("agent loop attempt callback failed")
	ErrResult        = errors.New("agent loop attempt result is invalid")
	ErrObserver      = errors.New("agent loop status callback failed")
	ErrDependency    = errors.New("agent loop scheduling dependency failed")
)

type Outcome string

const (
	Success       Outcome = "success"
	Retryable     Outcome = "retryable"
	Configuration Outcome = "configuration"
	State         Outcome = "state"
	Revoked       Outcome = "revoked"
)

// Metadata is the only information an attempt may return besides its outcome.
// Counts must each be at most three and their sum must be at most three. Sequence
// is an opaque unsigned counter; there is no device identity or observation data.
type Metadata struct {
	ProcessesStatus             string `json:"processesStatus,omitempty"`
	ProcessesSequence           uint64 `json:"processesSequence,omitempty"`
	VolumesStatus               string `json:"volumesStatus,omitempty"`
	VolumesSequence             uint64 `json:"volumesSequence,omitempty"`
	OverviewOperations          uint8  `json:"overviewOperations,omitempty"`
	JournalStatus               string `json:"journalStatus,omitempty"`
	Sequence                    uint64 `json:"sequence,omitempty"`
	Duplicate                   bool   `json:"duplicate"`
	RetriedPending              bool   `json:"retriedPending"`
	DiscardedStale              bool   `json:"discardedStale"`
	AvailablePercentageFields   uint8  `json:"availablePercentageFields"`
	UnavailablePercentageFields uint8  `json:"unavailablePercentageFields"`
	InventoryStatus             string `json:"inventoryStatus,omitempty"`
	InventorySequence           uint64 `json:"inventorySequence,omitempty"`
	InventoryOperations         uint8  `json:"inventoryOperations,omitempty"`
	SystemStatus                string `json:"systemStatus,omitempty"`
	SystemSequence              uint64 `json:"systemSequence,omitempty"`
	SystemRetriedPending        bool   `json:"systemRetriedPending,omitempty"`
	SystemDiscardedStale        bool   `json:"systemDiscardedStale,omitempty"`
}

// Result must use one of the five declared outcomes. The adapter is responsible
// for classifying its errors; the scheduler never accepts or inspects raw errors.
type Result struct {
	Outcome  Outcome
	Metadata Metadata
}

// Attempt must perform only the approved bounded read-only observation/delivery
// operation and cooperate with ctx. Run calls it synchronously. Cancellation
// cannot terminate a callback that ignores ctx; an OS supervisor must implement
// any required hard process deadline. Do not use this hook for remote commands.
type Attempt func(ctx context.Context) Result

type Config struct {
	// Zero selects DefaultInterval. Other values must be in [15s, 1h].
	Interval time.Duration
}

// Timer mirrors the minimal one-shot time.Timer contract. C must return a stable,
// non-nil channel that delivers once, no earlier than the requested delay. The
// channel must not be closed. Stop need not drain the channel; timers are not reused.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// Clock must be monotonic for elapsed measurements and start each timer when
// NewTimer is called. It is a trusted local dependency, not endpoint input.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

type Dependencies struct {
	Attempt Attempt
	// Observe receives at most three events per attempt and one final event.
	// It is synchronous, must return promptly, and must not retain unbounded logs.
	// Any error or panic stops scheduling without exposing its contents.
	Observe func(Event) error
	// Nil Clock/Random use the standard-library timer and jitter implementations.
	Clock Clock
	// Random must return a value in [0, maxExclusive). No cryptographic role.
	Random func(maxExclusive int64) int64
}

type Phase string

const (
	Starting Phase = "starting"
	Finished Phase = "finished"
	Waiting  Phase = "waiting"
	Stopped  Phase = "stopped"
)

type StopReason string

const (
	Cancelled            StopReason = "cancelled"
	Deadline             StopReason = "deadline"
	InvalidConfig        StopReason = "configuration"
	InvalidState         StopReason = "state"
	AuthorizationRevoked StopReason = "revoked"
	AttemptFailed        StopReason = "attempt_failed"
	InvalidResult        StopReason = "invalid_result"
	ObserverFailed       StopReason = "observer_failed"
	DependencyFailed     StopReason = "dependency_failed"
)

// Event is bounded status metadata, never telemetry. Outcome is empty before
// the first accepted result. Elapsed is clamped to [0, 1h], Delay to [0, 1h],
// and counters saturate rather than wrapping. No callback-provided string is
// emitted unless it is one of the five validated Outcome constants.
type Event struct {
	Phase               Phase         `json:"phase"`
	Attempt             uint64        `json:"attempt"`
	Outcome             Outcome       `json:"outcome,omitempty"`
	ConsecutiveFailures uint8         `json:"consecutiveFailures"`
	Delay               time.Duration `json:"delayNanoseconds"`
	Elapsed             time.Duration `json:"elapsedNanoseconds"`
	Metadata            Metadata      `json:"metadata"`
	Reason              StopReason    `json:"reason,omitempty"`
}

// Summary is returned even when the status observer fails. Callers should expose
// Reason and a fixed error classification rather than arbitrary adapter errors.
type Summary struct {
	Attempts            uint64     `json:"attempts"`
	LastOutcome         Outcome    `json:"lastOutcome,omitempty"`
	ConsecutiveFailures uint8      `json:"consecutiveFailures"`
	Reason              StopReason `json:"reason"`
}
