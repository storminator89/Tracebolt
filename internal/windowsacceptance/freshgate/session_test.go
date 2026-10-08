package freshgate

import (
	"context"
	"encoding/base64"
	"errors"
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
