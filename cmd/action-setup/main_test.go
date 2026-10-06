package main

import (
	"bytes"
	"testing"
)

func TestCapabilitiesInertAndModesExclusive(t *testing.T) {
	for _, args := range [][]string{{"--mode", "capabilities"}, {"--mode", "capabilities", "--endpoint", "x"}, {"--mode", "apply"}, {"--mode", "apply", "--confirm-plan", "wrong"}, {"--mode", "unknown"}} {
		var out, err bytes.Buffer
		code := run(args, bytes.NewReader([]byte(`{}`)), &out, &err)
		if len(args) == 2 && args[1] == "capabilities" {
			if code != 0 || out.Len() == 0 {
				t.Fatal(code)
			}
		} else if code == 0 {
			t.Fatal("invalid mode accepted")
		}
	}
}
