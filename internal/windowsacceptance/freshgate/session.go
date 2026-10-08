package freshgate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// OutputChunk never formats its potentially private pipe bytes. Its owner must
// clear Data after consumption. It is never encoded into acceptance evidence.
type OutputChunk struct {
	Data []byte
	Err  error
}

func (OutputChunk) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "<private console chunk>") }

type SessionSteps struct {
	Output                <-chan OutputChunk
	Exited, ConsoleClosed <-chan struct{}
	ProcessSucceeded      func() bool
	CloseConsole          func()
	Input                 func() error
	Approve               func() (bool, error)
}

// SessionOutcome is a finite diagnostic for the controller's stopping boundary.
// It never contains pipe output, callback errors or private runtime state.
type SessionOutcome string

const (
	SessionNotRun             SessionOutcome = "not_run"
	SessionInvalidSteps       SessionOutcome = "invalid_steps"
	SessionCancelled          SessionOutcome = "cancelled"
	SessionOutputRejected     SessionOutcome = "output_rejected"
	SessionOutputReadFailed   SessionOutcome = "output_read_failed"
	SessionOutputEOFMissing   SessionOutcome = "output_eof_missing"
	SessionInputFailed        SessionOutcome = "input_failed"
	SessionApprovalFailed     SessionOutcome = "approval_failed"
	SessionChildUnsuccessful  SessionOutcome = "child_unsuccessful"
	SessionProtocolIncomplete SessionOutcome = "protocol_incomplete"
	SessionPassed             SessionOutcome = "passed"
)

// ObserveSession preserves the error-only controller API.
func ObserveSession(ctx context.Context, guard *OutputGuard, s SessionSteps) error {
	_, err := ObserveSessionDiagnostic(ctx, guard, s)
	return err
}

// ObserveSessionDiagnostic is the actual controller loop. Callbacks are native
// only in the separately guarded Windows test; portable tests use inert mocks.
// A passed outcome requires child exit, complete output EOF, console closure
// and one successful Finish. The outcome describes the first observed stopping
// boundary, not a root cause. NotRun is reserved for owners that did not call
// the controller. Cancellation/error cleanup belongs to the resource owner.
func ObserveSessionDiagnostic(ctx context.Context, guard *OutputGuard, s SessionSteps) (SessionOutcome, error) {
	if ctx == nil || guard == nil || s.Output == nil || s.Exited == nil || s.ConsoleClosed == nil || s.ProcessSucceeded == nil || s.CloseConsole == nil || s.Input == nil || s.Approve == nil {
		return SessionInvalidSteps, ErrGuard
	}
	sent, approved, exited, eof, closed := false, false, false, false, false
	processDone := s.Exited
	chunks := s.Output
	consoleDone := (<-chan struct{})(nil)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return SessionCancelled, ErrGuard
		}
		if exited && eof && closed {
			if !sent || !approved {
				return SessionProtocolIncomplete, ErrGuard
			}
			if !s.ProcessSucceeded() {
				return SessionChildUnsuccessful, ErrGuard
			}
			if err := guard.Finish(); err != nil {
				return SessionProtocolIncomplete, err
			}
			return SessionPassed, nil
		}
		select {
		case <-ctx.Done():
			return SessionCancelled, ErrGuard
		case chunk, ok := <-chunks:
			if !ok {
				if !eof {
					return SessionOutputEOFMissing, ErrGuard
				}
				chunks = nil
				continue
			}
			e := guard.Feed(chunk.Data)
			clear(chunk.Data)
			if e != nil {
				return SessionOutputRejected, ErrGuard
			}
			if chunk.Err != nil {
				if !errors.Is(chunk.Err, io.EOF) {
					return SessionOutputReadFailed, ErrGuard
				}
				eof = true
				chunks = nil
			}
			if !sent && guard.PromptReady() {
				if ctx.Err() != nil {
					return SessionCancelled, ErrGuard
				}
				if guard.MarkInputSent() != nil {
					return SessionProtocolIncomplete, ErrGuard
				}
				if s.Input() != nil {
					return SessionInputFailed, ErrGuard
				}
				sent = true
			}
		case <-processDone:
			processDone = nil
			exited = true
			s.CloseConsole()
			consoleDone = s.ConsoleClosed
		case <-consoleDone:
			closed = true
			consoleDone = nil
		case <-ticker.C:
			if sent && !approved {
				if ctx.Err() != nil {
					return SessionCancelled, ErrGuard
				}
				ok, e := s.Approve()
				if e != nil {
					return SessionApprovalFailed, ErrGuard
				}
				approved = ok
			}
		}
	}
}
