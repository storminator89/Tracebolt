package main

import (
	"context"
	"testing"
)

func TestSetupConsoleOnlyControlCAndBreakCancelCooperatively(t *testing.T) {
	for _, event := range []uint32{0, 1, 2, 5, 6, 99} {
		ctx, cancel := context.WithCancel(context.Background())
		control := &setupConsoleControl{cancel: cancel}
		got := control.handle(event)
		expected := event == 0 || event == 1
		if got != expected || (ctx.Err() != nil) != expected {
			t.Fatal("control event semantics changed", event)
		}
		cancel()
	}
	var missing *setupConsoleControl
	if missing.handle(0) || (&setupConsoleControl{}).handle(1) {
		t.Fatal("missing binding handled control")
	}
}
