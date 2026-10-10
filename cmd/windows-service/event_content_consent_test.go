package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowsservice"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventContentRequiresOwnedStoppedService(t *testing.T) {
	receipt := windowsservice.Receipt{InstallationID: "fixture-owned-installation", Layout: windowsservice.Layout{EnrollmentRoot: "fixture-enrollment"}}
	for _, mode := range []string{"event-content-preview", "event-content-enable", "event-content-disable"} {
		for _, state := range []windowsservice.State{0, windowsservice.Stopped, windowsservice.Running, windowsservice.StartPending, windowsservice.StopPending} {
			for _, failed := range []bool{false, true} {
				calls, inspections := 0, 0
				_, err := eventContentOperation(context.Background(), request{mode: mode, insecureHTTP: true}, receipt,
					func(_ context.Context, got windowsservice.Receipt) (windowsservice.Snapshot, error) {
						inspections++
						if got != receipt {
							t.Fatal("ownership receipt changed")
						}
						if failed {
							return windowsservice.Snapshot{State: state}, errors.New("ownership rejected")
						}
						return windowsservice.Snapshot{State: state}, nil
					},
					func(path, gotMode string, ack, insecure bool) (lanclient.WindowsEventContentConsentResult, error) {
						calls++
						wantMode := map[string]string{"event-content-preview": "preview", "event-content-enable": "enable", "event-content-disable": "disable"}[mode]
						if path != filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json") || gotMode != wantMode || ack != (wantMode == "enable") || !insecure {
							t.Fatal("consent binding changed")
						}
						return lanclient.WindowsEventContentConsentResult{}, nil
					})
				allowed := !failed && state == windowsservice.Stopped
				if inspections != 1 || (err == nil) != allowed || (calls == 1) != allowed {
					t.Fatal(mode, state, failed, calls, err)
				}
			}
		}
	}
}

func TestEventContentConsentErrorsAndInvalidModes(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsEventContentConsentResult, error) {
		return lanclient.WindowsEventContentConsentResult{}, lanclient.ErrState
	}
	if _, err := eventContentOperation(context.Background(), request{mode: "event-content-enable"}, windowsservice.Receipt{}, inspect, configure); !errors.Is(err, lanclient.ErrState) {
		t.Fatal("consent failure hidden", err)
	}
	for _, mode := range []string{"", "install", "enroll", "volumes-enable"} {
		if _, err := eventContentOperation(context.Background(), request{mode: mode}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			t.Fatal("invalid mode touched service")
			return windowsservice.Snapshot{}, nil
		}, configure); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
}

func TestEventContentConsentNeverConfiguresWithMissingDependencies(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		t.Fatal("invalid invocation reached service")
		return windowsservice.Snapshot{}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsEventContentConsentResult, error) {
		t.Fatal("invalid invocation reached consent store")
		return lanclient.WindowsEventContentConsentResult{}, nil
	}
	r := request{mode: "event-content-enable"}
	if _, err := eventContentOperation(nil, r, windowsservice.Receipt{}, inspect, configure); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := eventContentOperation(context.Background(), r, windowsservice.Receipt{}, nil, configure); err == nil {
		t.Fatal("nil inspection accepted")
	}
	if _, err := eventContentOperation(context.Background(), r, windowsservice.Receipt{}, inspect, nil); err == nil {
		t.Fatal("nil configuration accepted")
	}
}

type eventContentDisclosureWriter struct {
	writes, failAt int
	short          bool
}

func (w *eventContentDisclosureWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, errors.New("fixture output failure")
	}
	return len(p), nil
}

func TestEventContentDisclosureMustCompleteBeforeDispatch(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, short := range []bool{false, true} {
			out := &eventContentDisclosureWriter{failAt: failAt, short: short}
			called := false
			code := runWith(context.Background(), []string{"--event-content-enable", "--apply", "--selected-application-system-event-messages", "--insecure-http-test"}, out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				called = true
				return nil, nil
			})
			if code != 1 || called || out.writes != failAt {
				t.Fatal("incomplete startup disclosure reached consent", failAt, short, code, called)
			}
		}
	}
}

func TestEventContentFlagsDoNotAuthorizeAnotherScope(t *testing.T) {
	for _, mode := range []string{"event-content-preview", "event-content-enable", "event-content-disable"} {
		for _, otherScope := range []string{"--basic-readonly", "--windows-inventory", "--application-system-event-headers", "--visible-volumes", "--process-cpu-memory", "--network-endpoints"} {
			args := []string{"--" + mode, otherScope}
			if mode != "event-content-preview" {
				args = append(args, "--apply")
			}
			if mode == "event-content-enable" {
				args = append(args, "--selected-application-system-event-messages")
			}
			code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				t.Fatal("extra scope reached operation")
				return nil, nil
			})
			if code != 2 {
				t.Fatal("unselected scope accepted", args)
			}
		}
	}
}

func TestEventContentConsentFlagsExplicitAndBounded(t *testing.T) {
	for _, args := range [][]string{{"--event-content-enable", "--apply"}, {"--event-content-enable", "--selected-application-system-event-messages"}, {"--event-content-preview", "--apply"}, {"--event-content-disable", "--apply", "--selected-application-system-event-messages"}, {"--install", "--apply", "--windows-inventory", "--selected-application-system-event-messages", "--bootstrap-file=C:\\fixture"}} {
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("invalid flags reached host seam")
			return nil, nil
		}); code != 2 {
			t.Fatal(args, code)
		}
	}
	for _, args := range [][]string{{"--event-content-preview"}, {"--event-content-preview", "--insecure-http-test"}, {"--event-content-enable", "--apply", "--selected-application-system-event-messages"}, {"--event-content-enable", "--apply", "--selected-application-system-event-messages", "--insecure-http-test"}, {"--event-content-disable", "--apply"}, {"--event-content-disable", "--apply", "--insecure-http-test"}} {
		called := false
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }); code != 0 || !called {
			t.Fatal(args, code, called)
		}
	}
}

func TestWindowsEventContentHelpDescribesIndependentScope(t *testing.T) {
	var out bytes.Buffer
	if code := runWith(context.Background(), []string{"--help"}, &out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
		t.Fatal("help reached host")
		return nil, nil
	}); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"--event-content-preview", "--event-content-enable --apply --selected-application-system-event-messages", "--event-content-disable --apply", "No automatic service restart.", windowseventrequest.Privacy, windowseventrequest.HTTPPrivacy} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("missing update help", want)
		}
	}
}

func TestWindowsEventContentCanceledInspectionCannotWriteConsent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := eventContentOperation(ctx, request{mode: "event-content-enable"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		cancel()
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}, func(string, string, bool, bool) (lanclient.WindowsEventContentConsentResult, error) {
		t.Fatal("canceled lifecycle wrote grant")
		return lanclient.WindowsEventContentConsentResult{}, nil
	})
	if err == nil {
		t.Fatal("canceled consent lifecycle succeeded")
	}
}
