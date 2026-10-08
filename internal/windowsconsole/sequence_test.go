package windowsconsole

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestDiagnosticChangesPreserveConsoleSequence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*fixtureConsole)
		promptErr error
		want      Category
		calls     []string
	}{
		{"success", func(*fixtureConsole) {}, nil, CategoryUnknown, []string{"mode", "set", "mode", "discard", "prompt", "read", "read", "discard", "set", "mode", "close"}},
		{"initial mode", func(f *fixtureConsole) { f.failMode = 1 }, nil, CategoryModeRead, []string{"mode", "close"}},
		{"hidden set", func(f *fixtureConsole) { f.failSet = 1 }, nil, CategoryModeSet, []string{"mode", "set", "discard", "set", "mode", "close"}},
		{"hidden verification", func(f *fixtureConsole) { f.failMode = 2 }, nil, CategoryModeVerify, []string{"mode", "set", "mode", "discard", "set", "mode", "close"}},
		{"type-ahead discard", func(f *fixtureConsole) { f.failDiscard = 1 }, nil, CategoryDiscard, []string{"mode", "set", "mode", "discard", "discard", "set", "mode", "close"}},
		{"prompt", func(*fixtureConsole) {}, hostileError{}, CategoryPrompt, []string{"mode", "set", "mode", "discard", "prompt", "discard", "set", "mode", "close"}},
		{"read", func(f *fixtureConsole) { f.failRead = 1 }, nil, CategoryRead, []string{"mode", "set", "mode", "discard", "prompt", "read", "discard", "set", "mode", "close"}},
		{"decode", func(f *fixtureConsole) { f.records = []inputRecord{key('!', 1)} }, nil, CategoryDecode, []string{"mode", "set", "mode", "discard", "prompt", "read", "discard", "set", "mode", "close"}},
		{"first cleanup wins", func(f *fixtureConsole) { f.failDiscard = 2; f.failSet = 2; f.failClose = true }, hostileError{}, CategoryCleanupDiscard, []string{"mode", "set", "mode", "discard", "prompt", "discard", "set", "close"}},
		{"restore precedes close", func(f *fixtureConsole) { f.failMode = 3; f.failClose = true }, hostileError{}, CategoryRestoreVerify, []string{"mode", "set", "mode", "discard", "prompt", "discard", "set", "mode", "close"}},
		{"close overrides primary", func(f *fixtureConsole) { f.failClose = true }, hostileError{}, CategoryClose, []string{"mode", "set", "mode", "discard", "prompt", "discard", "set", "mode", "close"}},
		{"original extended flag", func(f *fixtureConsole) { f.current &^= extendedFlags }, nil, CategoryUnknown, []string{"mode", "set", "mode", "discard", "prompt", "read", "read", "discard", "set", "set", "mode", "close"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureConsole()
			tc.change(f)
			original := f.current
			secret, err := runFixture(context.Background(), f, func() error {
				f.operations = append(f.operations, "prompt")
				return tc.promptErr
			})
			defer clear(secret)
			if !slices.Equal(f.operations, tc.calls) {
				t.Fatal("console call ordering changed")
			}
			if CategoryOf(err) != tc.want {
				t.Fatal("unexpected operation category")
			}
			if tc.want == CategoryUnknown {
				if err != nil || len(secret) != invitationLength {
					t.Fatal("valid sequence failed")
				}
			} else if secret != nil || !errors.Is(err, ErrInput) || errors.Unwrap(err) != ErrInput {
				t.Fatal("failure retained input or a raw cause")
			}
			if len(f.sets) > 0 && f.sets[0] != hiddenMode(original) {
				t.Fatal("hidden mode changed")
			}
			if len(f.sets) > 1 && f.sets[1] != original|extendedFlags {
				t.Fatal("restore mode changed")
			}
			if len(f.sets) > 2 && f.sets[2] != original {
				t.Fatal("exact restoration changed")
			}
		})
	}
}

func TestContextDiagnosticAtEveryBoundary(t *testing.T) {
	for _, boundary := range []string{"before open", "before prompt", "after prompt", "read", "completion", "cleanup"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixtureConsole()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prompt := func() error { return nil }
			switch boundary {
			case "before open":
				cancel()
			case "before prompt":
				f.onDiscard = func(call int) {
					if call == 1 {
						cancel()
					}
				}
			case "after prompt":
				prompt = func() error { cancel(); return nil }
			case "read":
				f.onRead = func(int) { cancel() }
			case "completion":
				f.onRead = func(call int) {
					if call == 2 {
						cancel()
					}
				}
			case "cleanup":
				f.onClose = cancel
			}
			promptCalls := 0
			secret, err := runFixture(ctx, f, func() error { promptCalls++; return prompt() })
			if secret != nil || CategoryOf(err) != CategoryContext || !errors.Is(err, ErrInput) || errors.Unwrap(err) != ErrInput {
				t.Fatal("cancellation retained input or lost finite category")
			}
			if boundary == "before open" {
				if len(f.operations) != 0 || promptCalls != 0 {
					t.Fatal("pre-cancellation performed console work")
				}
			} else if f.closeCalls != 1 || f.discardCalls != 2 {
				t.Fatal("cancellation omitted existing cleanup")
			}
			if boundary == "before prompt" && promptCalls != 0 {
				t.Fatal("prompt ran after cancellation")
			}
		})
	}
}
