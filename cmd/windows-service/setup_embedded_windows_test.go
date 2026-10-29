//go:build windows && tracebolt_setup

package main

import "testing"

func TestUnpersonalizedSourceBootstrapSentinel(t *testing.T) {
	raw, err := setupPayload.ReadFile("setup_payload/public-bootstrap.txt")
	if err != nil || string(raw) != "none" {
		t.Fatal("source placeholder must be the exact newline-free no-bootstrap sentinel")
	}
}
