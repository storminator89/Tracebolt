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

// ObserveSession is the actual controller loop. Callbacks are native only in
// the separately guarded Windows test; portable tests use inert channels/mocks.
// It returns only after child exit, complete output EOF, console closure and
// one successful Finish. Cancellation/error cleanup belongs to the resource owner.
func ObserveSession(ctx context.Context, guard *OutputGuard, s SessionSteps) error {
	if ctx == nil || guard == nil || s.Output == nil || s.Exited == nil || s.ConsoleClosed == nil || s.ProcessSucceeded == nil || s.CloseConsole == nil || s.Input == nil || s.Approve == nil {
		return ErrGuard
	}
	sent, approved, exited, eof, closed := false, false, false, false, false
	processDone := s.Exited
	chunks := s.Output
	consoleDone := (<-chan struct{})(nil)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ErrGuard
		}
		if exited && eof && closed {
			if !sent || !approved || !s.ProcessSucceeded() {
				return ErrGuard
			}
			return guard.Finish()
		}
		select {
		case <-ctx.Done():
			return ErrGuard
		case chunk, ok := <-chunks:
			if !ok {
				if !eof {
					return ErrGuard
				}
				chunks = nil
				continue
			}
			e := guard.Feed(chunk.Data)
			clear(chunk.Data)
			if e != nil {
				return ErrGuard
			}
			if chunk.Err != nil {
				if !errors.Is(chunk.Err, io.EOF) {
					return ErrGuard
				}
				eof = true
				chunks = nil
			}
			if !sent && guard.PromptReady() {
				if ctx.Err() != nil || guard.MarkInputSent() != nil || s.Input() != nil {
					return ErrGuard
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
					return ErrGuard
				}
				ok, e := s.Approve()
				if e != nil {
					return ErrGuard
				}
				approved = ok
			}
		}
	}
}
