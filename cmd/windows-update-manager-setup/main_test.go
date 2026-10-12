package main

import (
	"bytes"
	"testing"
)

func TestSetupCommandRequiresExactExplicitPhaseAndAcknowledgement(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"prepare", "--apply"}, {"prepare", "--lan-config", "missing", "--enrollment-config", "missing", "--device-id", "missing", "--approve-plan", "invented"}, {"finalize", "--apply", "--approve-plan", "invented"}, {"prepare", "--unknown"}, {"prepare", "--ack-selected-windows-update-install"}, {"prepare", "--additional-device", "--apply"}, {"finalize", "--additional-device", "--approve-plan", "invented"}, {"prepare", "--additional-device", "--ack-selected-windows-update-install"}} {
		var out bytes.Buffer
		if e := run(args, &out); e == nil || out.Len() != 0 {
			t.Fatal("unapproved or invalid operation", args, e)
		}
	}
}
