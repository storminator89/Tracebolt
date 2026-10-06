package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestArgumentBoundaryIsInert(t *testing.T) {
	for _, args := range [][]string{{"--build-info"}, {"--help"}, {"--policy", "/tmp/anything"}, {"--pid", "1"}, {"--build-info", "extra"}, {"capture"}, {"--"}} {
		calls := 0
		var out, err bytes.Buffer
		code := run(context.Background(), args, &out, &err, func(context.Context) error { calls++; return nil })
		expected := 2
		if len(args) == 1 && args[0] == "--build-info" {
			expected = 0
		}
		if code != expected || calls != 0 {
			t.Fatalf("args %q: code=%d calls=%d", args, code, calls)
		}
		if expected == 0 && !strings.Contains(out.String(), "deployment v2 activated-client contract required") {
			t.Fatal("missing source gate")
		}
	}
}
func TestEntryUsesOnlyInjectedRuntime(t *testing.T) {
	for _, failure := range []error{nil, errors.New("fixture")} {
		calls := 0
		var out, err bytes.Buffer
		code := run(context.Background(), nil, &out, &err, func(context.Context) error { calls++; return failure })
		expected := 0
		if failure != nil {
			expected = 1
		}
		if code != expected || calls != 1 {
			t.Fatal("entry boundary")
		}
	}
}
