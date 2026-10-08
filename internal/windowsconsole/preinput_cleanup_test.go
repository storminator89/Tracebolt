package windowsconsole

import (
	"context"
	"testing"
)

// The ordinary public ConPTY fixture deliberately aborts its prompt callback.
// Its expected CategoryPrompt must never hide cleanup failure or imply a read.
func TestPromptAbortRequiresVerifiedCleanup(t *testing.T) {
	cases := []struct {
		name  string
		want  Category
		alter func(*fixtureConsole)
	}{
		{"restored", CategoryPrompt, func(*fixtureConsole) {}},
		{"discard", CategoryCleanupDiscard, func(f *fixtureConsole) { f.failDiscard = 2 }},
		{"restore_set", CategoryRestoreSet, func(f *fixtureConsole) { f.failSet = 2 }},
		{"restore_read", CategoryRestoreVerify, func(f *fixtureConsole) { f.failMode = 3 }},
		{"restore_mismatch", CategoryRestoreVerify, func(f *fixtureConsole) { f.wrongMode = 3 }},
		{"close", CategoryClose, func(f *fixtureConsole) { f.failClose = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureConsole()
			c.alter(f)
			value, err := runFixture(context.Background(), f, func() error { return fixtureFailure })
			if len(value) != 0 || CategoryOf(err) != c.want || f.readCalls != 0 || f.closeCalls != 1 || f.discardCalls != 2 {
				t.Fatal("pre-input abort did not preserve cleanup boundary")
			}
		})
	}
}
