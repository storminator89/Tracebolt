package freshgate

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestSessionProductionPromptAndFiniteChildProtocol(t *testing.T) {
	secret := []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	defer clear(secret)
	g, e := NewOutputGuard(secret)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	out := make(chan OutputChunk, 4)
	exit := make(chan struct{})
	closed := make(chan struct{})
	sent, approved, closes := 0, 0, 0
	out <- OutputChunk{Data: []byte("Manager: fixture\r\nDevice SPKI SHA-256: " + strings.Repeat("a", 64) + "\r\nComparison: " + strings.Repeat("b", 32) + "\r\nCompare the complete public fingerprint and comparison value in the manager before approving.\r\n" + PublicPrompt)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e = ObserveSession(ctx, g, SessionSteps{Output: out, Exited: exit, ConsoleClosed: closed, ProcessSucceeded: func() bool { return true }, CloseConsole: func() { closes++; close(closed) }, Input: func() error { sent++; return nil }, Approve: func() (bool, error) {
		approved++
		if approved == 1 {
			return false, nil
		}
		out <- OutputChunk{Data: []byte("\r\n" + SuccessMarker + "\r\n")}
		out <- OutputChunk{Err: io.EOF}
		close(out)
		close(exit)
		return true, nil
	}})
	if e != nil || sent != 1 || approved != 2 || closes != 1 {
		t.Fatal("finite child protocol failed", e, sent, approved, closes)
	}
}
func TestSessionCancellationAndFaultBoundaries(t *testing.T) {
	for _, mode := range []string{"cancel", "input-fail", "approve-fail", "early-exit", "missing-close"} {
		t.Run(mode, func(t *testing.T) {
			secret := []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			defer clear(secret)
			g, _ := NewOutputGuard(secret)
			defer g.Close()
			out := make(chan OutputChunk, 2)
			exit := make(chan struct{})
			closed := make(chan struct{})
			out <- OutputChunk{Data: []byte("Device SPKI SHA-256: " + strings.Repeat("a", 64) + "\r\nComparison: " + strings.Repeat("b", 32) + "\r\n" + PublicPrompt)}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			if mode == "early-exit" {
				close(exit)
				close(out)
			}
			e := ObserveSession(ctx, g, SessionSteps{Output: out, Exited: exit, ConsoleClosed: closed, ProcessSucceeded: func() bool { return false }, CloseConsole: func() {
				if mode != "missing-close" {
					close(closed)
				}
			}, Input: func() error {
				if mode == "input-fail" {
					return errors.New("synthetic input failure")
				}
				return nil
			}, Approve: func() (bool, error) {
				if mode == "approve-fail" {
					return false, errors.New("synthetic approve failure")
				}
				return false, nil
			}})
			if e == nil {
				t.Fatal("incomplete lifecycle admitted")
			}
		})
	}
}

func TestSessionRejectsUnprovenDrainAndCancelledCallbacks(t *testing.T) {
	for _, mode := range []string{"non-eof", "closed-without-eof", "cancel-ready"} {
		t.Run(mode, func(t *testing.T) {
			secret := []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			defer clear(secret)
			g, _ := NewOutputGuard(secret)
			defer g.Close()
			out := make(chan OutputChunk, 4)
			exit := make(chan struct{})
			closed := make(chan struct{})
			calls := 0
			out <- OutputChunk{Data: []byte("Device SPKI SHA-256: " + strings.Repeat("a", 64) + "\r\nComparison: " + strings.Repeat("b", 32) + "\r\n" + PublicPrompt)}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "cancel-ready" {
				cancel()
			}
			e := ObserveSession(ctx, g, SessionSteps{Output: out, Exited: exit, ConsoleClosed: closed, ProcessSucceeded: func() bool { return true }, CloseConsole: func() { close(closed) }, Input: func() error { calls++; return nil }, Approve: func() (bool, error) {
				calls++
				out <- OutputChunk{Data: []byte("\r\n" + SuccessMarker + "\r\n")}
				if mode == "non-eof" {
					out <- OutputChunk{Err: errors.New("inert pipe failure")}
				}
				close(out)
				close(exit)
				return true, nil
			}})
			if e == nil {
				t.Fatal("unproven output drain admitted")
			}
			if mode == "cancel-ready" && calls != 0 {
				t.Fatal("callback after cancellation")
			}
		})
	}
}

func TestSessionOutcomeVocabulary(t *testing.T) {
	for outcome, want := range map[SessionOutcome]string{
		SessionNotRun:             "not_run",
		SessionInvalidSteps:       "invalid_steps",
		SessionCancelled:          "cancelled",
		SessionOutputRejected:     "output_rejected",
		SessionOutputReadFailed:   "output_read_failed",
		SessionOutputEOFMissing:   "output_eof_missing",
		SessionInputFailed:        "input_failed",
		SessionApprovalFailed:     "approval_failed",
		SessionChildUnsuccessful:  "child_unsuccessful",
		SessionProtocolIncomplete: "protocol_incomplete",
		SessionPassed:             "passed",
	} {
		if string(outcome) != want {
			t.Fatalf("unexpected session outcome: %q", outcome)
		}
	}
}

// This error must not be formatted or propagated into diagnostics. The pipe
// and callbacks can return arbitrary private errors; only fixed errors escape.
type privateSessionError struct{}

func (privateSessionError) Error() string { panic("private session error formatted") }

type diagnosticSessionFixture struct {
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	guard                                  *OutputGuard
	output                                 chan OutputChunk
	exited, closed                         chan struct{}
	steps                                  SessionSteps
	inputCalls, approveCalls, processCalls int
	closeCalls                             int
	consumed                               [][]byte
}

func newDiagnosticSessionFixture(t *testing.T) *diagnosticSessionFixture {
	t.Helper()
	secret := []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	defer clear(secret)
	g, err := NewOutputGuard(secret)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	f := &diagnosticSessionFixture{
		ctx: ctx, cancel: cancel, guard: g,
		output: make(chan OutputChunk, 8), exited: make(chan struct{}), closed: make(chan struct{}),
	}
	t.Cleanup(cancel)
	t.Cleanup(g.Close)
	f.steps = SessionSteps{
		Output: f.output, Exited: f.exited, ConsoleClosed: f.closed,
		Input:            func() error { f.inputCalls++; return nil },
		Approve:          func() (bool, error) { f.approveCalls++; return false, nil },
		ProcessSucceeded: func() bool { f.processCalls++; return true },
		CloseConsole:     func() { f.closeCalls++; close(f.closed) },
	}
	return f
}

func (f *diagnosticSessionFixture) queue(data string, err error) {
	b := []byte(data)
	f.consumed = append(f.consumed, b)
	f.output <- OutputChunk{Data: b, Err: err}
}

func (f *diagnosticSessionFixture) prompt() {
	f.queue("Device SPKI SHA-256: "+strings.Repeat("a", 64)+"\r\nComparison: "+strings.Repeat("b", 32)+"\r\n"+PublicPrompt, nil)
}

func (f *diagnosticSessionFixture) complete(tail string, eof error) {
	f.queue(tail, eof)
	close(f.output)
	close(f.exited)
}

func (f *diagnosticSessionFixture) checkCleared(t *testing.T) {
	t.Helper()
	for _, b := range f.consumed {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("consumed output buffer was not cleared")
		}
	}
}

func TestSessionDiagnosticInvalidSteps(t *testing.T) {
	for _, missing := range []string{"context", "guard", "output", "exited", "closed", "process", "close", "input", "approve"} {
		t.Run(missing, func(t *testing.T) {
			f := newDiagnosticSessionFixture(t)
			// Invalid arguments precede even an already-cancelled context.
			f.cancel()
			switch missing {
			case "context":
				f.ctx = nil
			case "guard":
				f.guard = nil
			case "output":
				f.steps.Output = nil
			case "exited":
				f.steps.Exited = nil
			case "closed":
				f.steps.ConsoleClosed = nil
			case "process":
				f.steps.ProcessSucceeded = nil
			case "close":
				f.steps.CloseConsole = nil
			case "input":
				f.steps.Input = nil
			case "approve":
				f.steps.Approve = nil
			}
			outcome, err := ObserveSessionDiagnostic(f.ctx, f.guard, f.steps)
			if outcome != SessionInvalidSteps || err != ErrGuard {
				t.Fatalf("invalid steps returned %q, %v", outcome, err)
			}
			if f.inputCalls+f.approveCalls+f.processCalls+f.closeCalls != 0 {
				t.Fatal("invalid steps invoked callback")
			}
		})
	}
}

func TestSessionDiagnosticOutputAndCallbackFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		want    SessionOutcome
		setup   func(*diagnosticSessionFixture)
		input   int
		approve int
	}{
		{"output rejection precedes pipe error", SessionOutputRejected, func(f *diagnosticSessionFixture) {
			f.queue("private\x00output", privateSessionError{})
		}, 0, 0},
		{"output rejection precedes EOF", SessionOutputRejected, func(f *diagnosticSessionFixture) {
			f.queue("private\x00output", io.EOF)
		}, 0, 0},
		{"pipe error precedes ready input", SessionOutputReadFailed, func(f *diagnosticSessionFixture) {
			f.prompt()
			chunk := <-f.output
			chunk.Err = privateSessionError{}
			f.output <- chunk
		}, 0, 0},
		{"closed without EOF", SessionOutputEOFMissing, func(f *diagnosticSessionFixture) {
			f.queue("public disclosure\r\n", nil)
			close(f.output)
		}, 0, 0},
		{"input error", SessionInputFailed, func(f *diagnosticSessionFixture) {
			f.prompt()
			f.steps.Input = func() error { f.inputCalls++; return privateSessionError{} }
		}, 1, 0},
		{"input error precedes cancellation", SessionInputFailed, func(f *diagnosticSessionFixture) {
			f.prompt()
			f.steps.Input = func() error { f.inputCalls++; f.cancel(); return privateSessionError{} }
		}, 1, 0},
		{"input cancellation", SessionCancelled, func(f *diagnosticSessionFixture) {
			f.prompt()
			f.steps.Input = func() error { f.inputCalls++; f.cancel(); return nil }
		}, 1, 0},
		{"approval error precedes true result", SessionApprovalFailed, func(f *diagnosticSessionFixture) {
			f.prompt()
			f.steps.Approve = func() (bool, error) { f.approveCalls++; return true, privateSessionError{} }
		}, 1, 1},
		{"approval error precedes cancellation", SessionApprovalFailed, func(f *diagnosticSessionFixture) {
			f.prompt()
			f.steps.Approve = func() (bool, error) { f.approveCalls++; f.cancel(); return false, privateSessionError{} }
		}, 1, 1},
		{"approval cancellation", SessionCancelled, func(f *diagnosticSessionFixture) {
			f.prompt()
			f.steps.Approve = func() (bool, error) { f.approveCalls++; f.cancel(); return true, nil }
		}, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDiagnosticSessionFixture(t)
			tc.setup(f)
			outcome, err := ObserveSessionDiagnostic(f.ctx, f.guard, f.steps)
			if outcome != tc.want || err != ErrGuard {
				t.Fatalf("unexpected diagnostic %q or non-fixed error", outcome)
			}
			if f.inputCalls != tc.input || f.approveCalls != tc.approve || f.processCalls != 0 || f.closeCalls != 0 {
				t.Fatal("unexpected callback count", f.inputCalls, f.approveCalls, f.processCalls, f.closeCalls)
			}
			f.checkCleared(t)
		})
	}
}

func TestSessionDiagnosticCompletionPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		prompt      bool
		approve     bool
		process     bool
		tail        string
		want        SessionOutcome
		wantError   error
		wantProcess int
	}{
		{"missing input before child status", false, false, false, "", SessionProtocolIncomplete, ErrGuard, 0},
		{"missing approval before child status", true, false, false, "\r\n", SessionProtocolIncomplete, ErrGuard, 0},
		{"child status before unfinished protocol", true, true, false, "\r\n", SessionChildUnsuccessful, ErrGuard, 1},
		{"child unsuccessful after marker", true, true, false, "\r\n" + SuccessMarker + "\r\n", SessionChildUnsuccessful, ErrGuard, 1},
		{"missing marker", true, true, true, "\r\n", SessionProtocolIncomplete, ErrOutputGuard, 1},
		{"unfinished parser", true, true, true, "\r\n" + SuccessMarker + "\r\n\x1b", SessionProtocolIncomplete, ErrOutputGuard, 1},
		{"passed", true, true, true, "\r\n" + SuccessMarker + "\r\n", SessionPassed, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDiagnosticSessionFixture(t)
			f.steps.ProcessSucceeded = func() bool { f.processCalls++; return tc.process }
			if tc.prompt {
				f.prompt()
			}
			if tc.approve {
				f.steps.Approve = func() (bool, error) {
					f.approveCalls++
					// Retain the existing false-then-true polling protocol.
					if f.approveCalls == 1 {
						return false, nil
					}
					f.complete(tc.tail, fmt.Errorf("wrapped EOF: %w", io.EOF))
					return true, nil
				}
			} else {
				f.complete(tc.tail, io.EOF)
			}
			outcome, err := ObserveSessionDiagnostic(f.ctx, f.guard, f.steps)
			if outcome != tc.want || err != tc.wantError {
				t.Fatalf("got %q, %v; want %q, %v", outcome, err, tc.want, tc.wantError)
			}
			if f.processCalls != tc.wantProcess || f.closeCalls != 1 {
				t.Fatal("completion callbacks changed", f.processCalls, f.closeCalls)
			}
			if tc.prompt && f.inputCalls != 1 || !tc.prompt && f.inputCalls != 0 || tc.approve && f.approveCalls != 2 {
				t.Fatal("input/approval callback count changed", f.inputCalls, f.approveCalls)
			}
			if f.guard.state.finished != (tc.want == SessionPassed) {
				t.Fatal("guard Finish ran before successful completion")
			}
			f.checkCleared(t)
		})
	}
}

// Err hooks exercise serialized boundary changes without races or sleeps.
// Done and Err still come from the underlying cancellable context.
type sessionBoundaryContext struct {
	context.Context
	beforeErr func()
}

func (c sessionBoundaryContext) Err() error {
	c.beforeErr()
	return c.Context.Err()
}

func TestSessionDiagnosticCancellationAndInputBarrier(t *testing.T) {
	t.Run("idle cancellation", func(t *testing.T) {
		f := newDiagnosticSessionFixture(t)
		ctx, cancel := context.WithTimeout(f.ctx, 10*time.Millisecond)
		defer cancel()
		outcome, err := ObserveSessionDiagnostic(ctx, f.guard, f.steps)
		if outcome != SessionCancelled || err != ErrGuard || f.inputCalls+f.approveCalls+f.processCalls+f.closeCalls != 0 {
			t.Fatal("idle cancellation invoked work")
		}
	})
	t.Run("already cancelled leaves unread output owned by caller", func(t *testing.T) {
		f := newDiagnosticSessionFixture(t)
		f.prompt()
		original := bytes.Clone(f.consumed[0])
		f.cancel()
		outcome, err := ObserveSessionDiagnostic(f.ctx, f.guard, f.steps)
		if outcome != SessionCancelled || err != ErrGuard || f.inputCalls+f.approveCalls+f.processCalls+f.closeCalls != 0 {
			t.Fatal("cancelled session invoked work")
		}
		if !bytes.Equal(original, f.consumed[0]) {
			t.Fatal("controller consumed output after cancellation")
		}
		clear(original)
		clear(f.consumed[0])
	})
	t.Run("cancel at approval boundary", func(t *testing.T) {
		f := newDiagnosticSessionFixture(t)
		f.prompt()
		checksAfterInput := 0
		ctx := sessionBoundaryContext{Context: f.ctx, beforeErr: func() {
			if f.inputCalls == 0 {
				return
			}
			checksAfterInput++
			// After input: loop entry, then the approval boundary. No
			// other channel can become ready in this fixture.
			if checksAfterInput == 2 {
				f.cancel()
			}
		}}
		outcome, err := ObserveSessionDiagnostic(ctx, f.guard, f.steps)
		if outcome != SessionCancelled || err != ErrGuard || f.inputCalls != 1 || f.approveCalls+f.processCalls+f.closeCalls != 0 {
			t.Fatal("approval callback ran after cancellation")
		}
		f.checkCleared(t)
	})
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("input boundary cancelled=%t", cancel), func(t *testing.T) {
			f := newDiagnosticSessionFixture(t)
			f.prompt()
			ctx := sessionBoundaryContext{Context: f.ctx, beforeErr: func() {
				if f.guard.PromptReady() {
					// Invalidate the guard between readiness and input marking.
					// Cancellation must win when both boundaries fail.
					f.guard.Close()
					if cancel {
						f.cancel()
					}
				}
			}}
			want := SessionProtocolIncomplete
			if cancel {
				want = SessionCancelled
			}
			outcome, err := ObserveSessionDiagnostic(ctx, f.guard, f.steps)
			if outcome != want || err != ErrGuard || f.inputCalls+f.approveCalls+f.processCalls+f.closeCalls != 0 {
				t.Fatalf("input barrier returned %q or invoked callbacks", outcome)
			}
			f.checkCleared(t)
		})
	}
}

func TestSessionDiagnosticEOFDoesNotRequireChannelClosure(t *testing.T) {
	f := newDiagnosticSessionFixture(t)
	f.prompt()
	f.steps.Approve = func() (bool, error) {
		f.approveCalls++
		f.queue("\r\n"+SuccessMarker+"\r\n", io.EOF)
		close(f.exited)
		return true, nil
	}
	outcome, err := ObserveSessionDiagnostic(f.ctx, f.guard, f.steps)
	if outcome != SessionPassed || err != nil || f.inputCalls != 1 || f.approveCalls != 1 || f.processCalls != 1 || f.closeCalls != 1 {
		t.Fatal("confirmed EOF on open channel did not finish")
	}
	f.checkCleared(t)
}
