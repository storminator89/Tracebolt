package main

import (
	"bytes"
	"context"
	"localrmm/internal/lanclient"
	"strings"
	"testing"
)

func TestMacOSInventoryCommandNeverFallsThroughToBasic(t *testing.T) {
	var out, errOut bytes.Buffer
	inventoryCalls, basicCalls := 0, 0
	d := dependencies{platform: "darwin", uid: func() int { return 501 }, inventory: func(string) (bool, error) { return true, nil }, inventoryOnce: func(context.Context, string) error { inventoryCalls++; return nil }, once: func(context.Context, string) (lanclient.Report, error) { basicCalls++; return lanclient.Report{}, nil }}
	if result := run(context.Background(), []string{"--config", "/private/endpoint/agent.json"}, &out, &errOut, d); result != 0 || inventoryCalls != 1 || basicCalls != 0 || !strings.Contains(out.String(), "tracebolt.macos-inventory-run.v1") {
		t.Fatal("inventory dispatch failed", result, out.String(), errOut.String())
	}
	d.inventoryOnce = nil
	out.Reset()
	if result := run(context.Background(), []string{"--config", "/private/endpoint/agent.json"}, &out, &errOut, d); result != 2 || basicCalls != 0 || out.Len() != 0 {
		t.Fatal("missing inventory dispatcher fell through")
	}
}
func TestMacOSInventoryCommandRejectsCustomCadence(t *testing.T) {
	d := dependencies{platform: "darwin", uid: func() int { return 501 }, inventory: func(string) (bool, error) { return true, nil }}
	var out, errOut bytes.Buffer
	if run(context.Background(), []string{"--config", "/private/endpoint/agent.json", "--foreground", "--interval", "15s"}, &out, &errOut, d) != 2 {
		t.Fatal("fast cadence allowed")
	}
}
