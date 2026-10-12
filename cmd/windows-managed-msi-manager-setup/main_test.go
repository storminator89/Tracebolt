package main

import (
	"bytes"
	"testing"
)

func TestManagedManagerSetupRequiresSeparateExactApplyApproval(t *testing.T) {
	for _, args := range [][]string{nil, {"prepare"}, {"finalize"}, {"prepare", "--lan-config", "/inert/config", "--enrollment-config", "/inert/enrollment", "--device-id", "agent_11111111111111111111111111111111", "--apply"}, {"prepare", "--lan-config", "/inert/config", "--enrollment-config", "/inert/enrollment", "--device-id", "agent_11111111111111111111111111111111", "--ack-managed-msi-delivery-install"}, {"prepare", "--additional-device"}, {"prepare", "--ack-prepared-msi-install"}} {
		var out bytes.Buffer
		if e := run(args, &out); e == nil || out.Len() != 0 {
			t.Fatal("invalid setup invocation escaped", args, e)
		}
	}
}
