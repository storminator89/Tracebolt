package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/agentloop"
	"localrmm/internal/enrollmentclient"
	"strings"
	"testing"
	"time"
)

func pendingOptionsFixture() pendingServiceOptions {
	return pendingServiceOptions{BootstrapPath: "/fixture/bootstrap.json", StateDirectory: "/fixture/enrollment", ConfigPath: "/fixture/enrollment/agent.json", Identity: "1001:1001", Interval: 30 * time.Second}
}
func pendingHooksFixture(events *[]string) pendingServiceHooks {
	return pendingServiceHooks{
		identity: func(string) bool { *events = append(*events, "identity"); return true },
		load: func(string) (enrollmentclient.Bootstrap, error) {
			*events = append(*events, "bootstrap")
			return enrollmentclient.Bootstrap{Profile: "tls"}, nil
		},
		inspect: func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error) {
			*events = append(*events, "inspect")
			return enrollmentclient.ServiceState{Ready: true, ConfigPath: pendingOptionsFixture().ConfigPath}, nil
		},
		resume: func(context.Context, enrollmentclient.Bootstrap, string, bool, func(enrollmentclient.Progress) error) (enrollmentclient.Result, error) {
			*events = append(*events, "resume")
			return enrollmentclient.Result{}, nil
		},
		markReady: func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error) {
			*events = append(*events, "mark-ready")
			return enrollmentclient.ServiceState{Ready: true, ConfigPath: pendingOptionsFixture().ConfigPath}, nil
		},
		stopDeadline: func(enrollmentclient.Bootstrap, string, bool) error {
			*events = append(*events, "stop-deadline")
			return enrollmentclient.ErrServiceDeadline
		},
		sender: func(context.Context, string, time.Duration, io.Writer) error {
			*events = append(*events, "sender")
			return nil
		},
		wait: func(context.Context) error { *events = append(*events, "wait"); return context.Canceled },
	}
}
func TestPendingServiceIdentityBeforeAllPrivateState(t *testing.T) {
	events := []string{}
	h := pendingHooksFixture(&events)
	h.identity = func(string) bool { events = append(events, "identity"); return false }
	var out, stderr bytes.Buffer
	if runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h) != 2 || strings.Join(events, ",") != "identity" {
		t.Fatal("identity checked too late", events)
	}
}
func TestPendingServiceCompletedReadyUsesOfflineSenderPath(t *testing.T) {
	events := []string{}
	h := pendingHooksFixture(&events)
	var out, stderr bytes.Buffer
	if runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h) != 0 || strings.Join(events, ",") != "identity,bootstrap,inspect,mark-ready,sender" {
		t.Fatal("ready required network or wrong ordering", events)
	}
}
func TestPendingServiceNeverConstructsSenderBeforeValidatedReady(t *testing.T) {
	for _, failure := range []error{enrollmentclient.ErrTerminal, enrollmentclient.ErrState, enrollmentclient.ErrServiceDeadline, context.DeadlineExceeded} {
		events := []string{}
		h := pendingHooksFixture(&events)
		h.inspect = func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error) {
			events = append(events, "inspect-pending")
			return enrollmentclient.ServiceState{}, nil
		}
		h.resume = func(context.Context, enrollmentclient.Bootstrap, string, bool, func(enrollmentclient.Progress) error) (enrollmentclient.Result, error) {
			events = append(events, "resume")
			return enrollmentclient.Result{}, failure
		}
		var out, stderr bytes.Buffer
		runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h)
		if strings.Contains(strings.Join(events, ","), "sender") || strings.Contains(strings.Join(events, ","), "mark-ready") {
			t.Fatal("preactivation constructed sender", events)
		}
	}
	events := []string{}
	h := pendingHooksFixture(&events)
	count := 0
	h.inspect = func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error) {
		count++
		events = append(events, "inspect")
		return enrollmentclient.ServiceState{Ready: count > 1, ConfigPath: pendingOptionsFixture().ConfigPath}, nil
	}
	var out, stderr bytes.Buffer
	if runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h) != 0 || strings.Join(events, ",") != "identity,bootstrap,inspect,resume,inspect,mark-ready,sender" {
		t.Fatal("pending-to-ready ordering", events)
	}
}
func TestPendingServiceLocalDeadlineLatchesWithoutNetwork(t *testing.T) {
	events := []string{}
	h := pendingHooksFixture(&events)
	h.inspect = func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error) {
		events = append(events, "inspect")
		return enrollmentclient.ServiceState{}, enrollmentclient.ErrServiceDeadline
	}
	var out, stderr bytes.Buffer
	if runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h) != 2 || strings.Join(events, ",") != "identity,bootstrap,inspect,stop-deadline" {
		t.Fatal("deadline performed work or failed to latch", events)
	}
}
func TestPendingServicePermanentSenderErrorsPreventRestart(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{{agentloop.ErrState, 2}, {agentloop.ErrConfiguration, 2}, {agentloop.ErrRevoked, 2}, {enrollmentclient.ErrState, 2}, {context.Canceled, 0}, {errors.New("transient fixture"), 1}} {
		events := []string{}
		h := pendingHooksFixture(&events)
		h.sender = func(context.Context, string, time.Duration, io.Writer) error { return tc.err }
		var out, stderr bytes.Buffer
		if got := runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h); got != tc.code {
			t.Fatal("sender error classification", got, tc.code)
		}
	}
}
func TestPendingServiceRejectsHTTPMismatchBeforeInspection(t *testing.T) {
	events := []string{}
	h := pendingHooksFixture(&events)
	h.load = func(string) (enrollmentclient.Bootstrap, error) {
		events = append(events, "bootstrap")
		return enrollmentclient.Bootstrap{Profile: "http-test"}, nil
	}
	var out, stderr bytes.Buffer
	if runPendingService(context.Background(), pendingOptionsFixture(), &out, &stderr, h) != 2 || strings.Join(events, ",") != "identity,bootstrap" {
		t.Fatal("HTTP mismatch inspected state")
	}
}
