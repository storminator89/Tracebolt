package main

import (
	"context"
	"io"
	"testing"
)

func TestWindowsActionSetupRequiresExactLocalApproval(t *testing.T) {
	for _, args := range [][]string{nil, {"--apply"}, {"--policy-file", "fixture", "--apply"}, {"--policy-file", "fixture", "--approve", "sha256:bad"}, {"--policy-file", "fixture", "--shell", "powershell"}} {
		calls := 0
		code := runActionSetup(context.Background(), args, io.Discard, io.Discard, func(context.Context, actionSetupInput) error { calls++; return nil })
		if code != 2 || calls != 0 {
			t.Fatal("unapproved setup admitted", args, code, calls)
		}
	}
}
