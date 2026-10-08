package windowsconsole

import (
	"errors"
	"slices"
	"testing"
)

func TestOpenSequenceUsesOnlyExistingOperations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolveErr error
		openErr    error
		nilConsole bool
		typeErr    error
		wrongType  bool
		closeErr   bool
		want       Category
		wantCalls  []string
		wantClose  int
	}{
		{name: "resolve", resolveErr: hostileError{}, want: CategoryResolve, wantCalls: []string{"resolve"}},
		{name: "open", openErr: hostileError{}, want: CategoryOpen, wantCalls: []string{"resolve", "open"}},
		{name: "nil console", nilConsole: true, want: CategoryOpen, wantCalls: []string{"resolve", "open"}},
		{name: "type API", typeErr: hostileError{}, want: CategoryType, wantCalls: []string{"resolve", "open", "type"}, wantClose: 1},
		{name: "wrong type", wrongType: true, want: CategoryType, wantCalls: []string{"resolve", "open", "type"}, wantClose: 1},
		{name: "type cleanup", wrongType: true, closeErr: true, want: CategoryClose, wantCalls: []string{"resolve", "open", "type"}, wantClose: 1},
		{name: "success", want: CategoryUnknown, wantCalls: []string{"resolve", "open", "type"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureConsole()
			f.failClose = tc.closeErr
			var calls []string
			c, err := openVerifiedConsole(func() error {
				calls = append(calls, "resolve")
				return tc.resolveErr
			}, func() (console, error) {
				calls = append(calls, "open")
				if tc.nilConsole || tc.openErr != nil {
					return nil, tc.openErr
				}
				return f, nil
			}, func(c console) (bool, error) {
				calls = append(calls, "type")
				if c != f {
					t.Fatal("type check lost opened console")
				}
				return !tc.wrongType, tc.typeErr
			})
			if !slices.Equal(calls, tc.wantCalls) || f.closeCalls != tc.wantClose || f.modeCalls != 0 || f.setCalls != 0 || f.discardCalls != 0 || f.readCalls != 0 {
				t.Fatal("open operation ordering or count changed")
			}
			if tc.want == CategoryUnknown {
				if c != f || err != nil {
					t.Fatal("valid console was not returned")
				}
			} else if c != nil || CategoryOf(err) != tc.want || !errors.Is(err, ErrInput) || errors.Unwrap(err) != ErrInput {
				t.Fatal("open category or sanitized error chain differs")
			}
		})
	}
}
