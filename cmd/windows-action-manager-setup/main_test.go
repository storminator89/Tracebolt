package main

import (
	"bytes"
	"testing"
)

func TestWindowsServiceActionSetupRequiresExactExplicitArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--apply"}, {"--lan-config", "missing", "--enrollment-config", "missing", "--binding-file", "missing", "--approve-plan", "sha256:invented"}, {"--unknown"}, {"--lan-config", "missing", "--enrollment-config", "missing", "--binding-file", "missing", "--apply", "--ack-windows-service-control"}} {
		var out bytes.Buffer
		if e := run(args, &out); e == nil || out.Len() != 0 {
			t.Fatal("unapproved or unverified setup", args, e)
		}
	}
}
