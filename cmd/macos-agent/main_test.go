package main

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"localrmm/internal/lanclient"
	"strings"
	"testing"
	"time"
)

func TestMacOSAgentRejectsBeforeStateAccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		platform string
		uid      int
	}{
		{"linux", []string{"--config", "/private/agent.json"}, "linux", 501},
		{"root", []string{"--config", "/private/agent.json"}, "darwin", 0},
		{"relative", []string{"--config", "agent.json"}, "darwin", 501},
		{"unknown-scope", []string{"--config", "/private/agent.json", "--read-admin"}, "darwin", 501},
		{"interval", []string{"--config", "/private/agent.json", "--foreground", "--interval", "1s"}, "darwin", 501},
		{"service-once", []string{"--config", "/private/agent.json", "--service-identity", "501:20"}, "darwin", 501},
		{"service-identity", []string{"--config", "/private/agent.json", "--foreground", "--service-identity", "501:20"}, "darwin", 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			d := dependencies{platform: tc.platform, uid: func() int { return tc.uid }, identity: func(string) bool { return false }, validate: func(string) error { calls++; return nil }, once: func(context.Context, string) (lanclient.Report, error) { calls++; return lanclient.Report{}, nil }, foreground: func(context.Context, string, time.Duration, func(agentloop.Event) error) (agentloop.Summary, error) {
				calls++
				return agentloop.Summary{}, nil
			}}
			var out, err bytes.Buffer
			if run(context.Background(), tc.args, &out, &err, d) != 2 || calls != 0 || out.Len() != 0 {
				t.Fatal("rejected invocation performed work")
			}
		})
	}
}
func TestMacOSAgentReadOnlyValidationAndSafeFailure(t *testing.T) {
	var out, stderr bytes.Buffer
	calls := 0
	d := dependencies{platform: "darwin", uid: func() int { return 501 }, validate: func(path string) error {
		calls++
		if path != "/private/agent.json" {
			t.Fatal("path changed")
		}
		return nil
	}}
	if run(context.Background(), []string{"--config", "/private/agent.json", "--validate-guided"}, &out, &stderr, d) != 0 || calls != 1 {
		t.Fatal("validation failed")
	}
	d.once = func(context.Context, string) (lanclient.Report, error) {
		return lanclient.Report{}, errors.New("secret-or-private-path")
	}
	out.Reset()
	stderr.Reset()
	if run(context.Background(), []string{"--config", "/private/agent.json"}, &out, &stderr, d) != 1 || strings.Contains(stderr.String(), "secret-or-private-path") || out.Len() != 0 {
		t.Fatal("failure leaked raw error or reported success")
	}
}
func TestMacOSAgentForegroundUsesRenewableSchedulerAndCancellation(t *testing.T) {
	var out, stderr bytes.Buffer
	calls := 0
	d := dependencies{platform: "darwin", uid: func() int { return 501 }, foreground: func(ctx context.Context, path string, interval time.Duration, observe func(agentloop.Event) error) (agentloop.Summary, error) {
		calls++
		if path != "/private/agent.json" || interval != 45*time.Second {
			t.Fatal("scheduler contract changed")
		}
		return agentloop.Summary{}, context.Canceled
	}}
	if run(context.Background(), []string{"--config", "/private/agent.json", "--foreground", "--interval", "45s"}, &out, &stderr, d) != 0 || calls != 1 {
		t.Fatal("foreground did not stop cleanly")
	}
}
