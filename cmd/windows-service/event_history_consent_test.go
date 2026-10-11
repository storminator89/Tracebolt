package main

import (
	"bytes"
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowsservice"
	"strings"
	"testing"
)

func TestEventHistoryConsentExplicitSeparateAndDisclosed(t *testing.T) {
	for _, args := range [][]string{{"--event-history-enable", "--apply"}, {"--event-history-enable", "--apply", "--selected-application-system-event-messages"}, {"--event-content-enable", "--apply", "--application-system-event-history-and-messages"}, {"--event-history-disable", "--apply", "--application-system-event-history-and-messages"}, {"--event-history-enable", "--application-system-event-history-and-messages"}} {
		if runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("cross-scope or missing approval dispatched")
			return nil, nil
		}) != 2 {
			t.Fatal("flags accepted")
		}
	}
	for _, insecure := range []bool{false, true} {
		args := []string{"--event-history-enable", "--apply", "--application-system-event-history-and-messages"}
		if insecure {
			args = append(args, "--insecure-http-test")
		}
		var out bytes.Buffer
		calls := 0
		if runWith(context.Background(), args, &out, io.Discard, func(_ context.Context, r request, _, _ io.Writer) (any, error) {
			calls++
			if r.mode != "event-history-enable" || r.insecureHTTP != insecure || !strings.Contains(out.String(), windowshistoryrequest.Privacy) || insecure && !strings.Contains(out.String(), windowshistoryrequest.HTTPPrivacy) {
				t.Fatal("missing history warning")
			}
			return nil, nil
		}) != 0 || calls != 1 {
			t.Fatal("history dispatch")
		}
	}
	for _, short := range []bool{false, true} {
		for _, failAt := range []int{1, 2} {
			out := &eventContentDisclosureWriter{short: short, failAt: failAt}
			if runWith(context.Background(), []string{"--event-history-enable", "--apply", "--application-system-event-history-and-messages", "--insecure-http-test"}, out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				t.Fatal("incomplete warning dispatched")
				return nil, nil
			}) != 1 {
				t.Fatal("warning failure hidden")
			}
		}
	}
}
func TestEventHistoryConsentOwnedStoppedAndCancellationGuard(t *testing.T) {
	for _, state := range []windowsservice.State{windowsservice.Stopped, windowsservice.Running, windowsservice.StartPending} {
		for _, cancelInspection := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			calls := 0
			_, e := eventHistoryOperation(ctx, request{mode: "event-history-enable"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				if cancelInspection {
					cancel()
				}
				return windowsservice.Snapshot{State: state}, nil
			}, func(string, string, bool, bool) (lanclient.WindowsEventHistoryConsentResult, error) {
				calls++
				return lanclient.WindowsEventHistoryConsentResult{}, nil
			})
			cancel()
			allowed := state == windowsservice.Stopped && !cancelInspection
			if (e == nil) != allowed || (calls == 1) != allowed {
				t.Fatal("unowned/running/canceled grant")
			}
		}
	}
}
