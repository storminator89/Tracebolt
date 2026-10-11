package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdates"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdatesRequiresOwnedStoppedService(t *testing.T) {
	receipt := windowsservice.Receipt{InstallationID: "fixture-owned-installation", Layout: windowsservice.Layout{EnrollmentRoot: "fixture-enrollment"}}
	for _, mode := range []string{"updates-preview", "updates-enable", "updates-disable"} {
		for _, state := range []windowsservice.State{0, windowsservice.Stopped, windowsservice.Running, windowsservice.StartPending, windowsservice.StopPending} {
			for _, failed := range []bool{false, true} {
				calls, inspections := 0, 0
				_, err := updatesOperation(context.Background(), request{mode: mode, insecureHTTP: true}, receipt,
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
					func(path, gotMode string, ack, insecure bool) (lanclient.WindowsUpdatesConsentResult, error) {
						calls++
						wantMode := map[string]string{"updates-preview": "preview", "updates-enable": "enable", "updates-disable": "disable"}[mode]
						if path != filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json") || gotMode != wantMode || ack != (wantMode == "enable") || !insecure {
							t.Fatal("consent binding changed")
						}
						return lanclient.WindowsUpdatesConsentResult{}, nil
					})
				allowed := !failed && state == windowsservice.Stopped
				if inspections != 1 || (err == nil) != allowed || (calls == 1) != allowed {
					t.Fatal(mode, state, failed, calls, err)
				}
			}
		}
	}
}

func TestUpdatesConsentErrorsAndInvalidModes(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsUpdatesConsentResult, error) {
		return lanclient.WindowsUpdatesConsentResult{}, lanclient.ErrState
	}
	if _, err := updatesOperation(context.Background(), request{mode: "updates-enable"}, windowsservice.Receipt{}, inspect, configure); !errors.Is(err, lanclient.ErrState) {
		t.Fatal("consent failure hidden", err)
	}
	for _, mode := range []string{"", "install", "enroll", "volumes-enable"} {
		if _, err := updatesOperation(context.Background(), request{mode: mode}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			t.Fatal("invalid mode touched service")
			return windowsservice.Snapshot{}, nil
		}, configure); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
}

func TestUpdatesConsentNeverConfiguresWithMissingDependencies(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		t.Fatal("invalid invocation reached service")
		return windowsservice.Snapshot{}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsUpdatesConsentResult, error) {
		t.Fatal("invalid invocation reached consent store")
		return lanclient.WindowsUpdatesConsentResult{}, nil
	}
	r := request{mode: "updates-enable"}
	if _, err := updatesOperation(nil, r, windowsservice.Receipt{}, inspect, configure); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := updatesOperation(context.Background(), r, windowsservice.Receipt{}, nil, configure); err == nil {
		t.Fatal("nil inspection accepted")
	}
	if _, err := updatesOperation(context.Background(), r, windowsservice.Receipt{}, inspect, nil); err == nil {
		t.Fatal("nil configuration accepted")
	}
}

type updatesDisclosureWriter struct {
	writes, failAt int
	short          bool
}

func (w *updatesDisclosureWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, errors.New("fixture output failure")
	}
	return len(p), nil
}

func TestUpdatesDisclosureMustCompleteBeforeDispatch(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, short := range []bool{false, true} {
			out := &updatesDisclosureWriter{failAt: failAt, short: short}
			called := false
			code := runWith(context.Background(), []string{"--updates-enable", "--apply", "--cached-windows-updates", "--insecure-http-test"}, out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				called = true
				return nil, nil
			})
			if code != 1 || called || out.writes != failAt {
				t.Fatal("incomplete startup disclosure reached consent", failAt, short, code, called)
			}
		}
	}
}

func TestUpdatesFlagsDoNotAuthorizeAnotherScope(t *testing.T) {
	for _, mode := range []string{"updates-preview", "updates-enable", "updates-disable"} {
		for _, otherScope := range []string{"--basic-readonly", "--windows-inventory", "--application-system-event-headers", "--visible-volumes", "--process-cpu-memory", "--network-endpoints"} {
			args := []string{"--" + mode, otherScope}
			if mode != "updates-preview" {
				args = append(args, "--apply")
			}
			if mode == "updates-enable" {
				args = append(args, "--cached-windows-updates")
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

func TestUpdatesConsentFlagsExplicitAndBounded(t *testing.T) {
	for _, args := range [][]string{{"--updates-enable", "--apply"}, {"--updates-enable", "--cached-windows-updates"}, {"--updates-preview", "--apply"}, {"--updates-disable", "--apply", "--cached-windows-updates"}, {"--install", "--apply", "--windows-inventory", "--cached-windows-updates", "--bootstrap-file=C:\\fixture"}} {
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("invalid flags reached host seam")
			return nil, nil
		}); code != 2 {
			t.Fatal(args, code)
		}
	}
	for _, args := range [][]string{{"--updates-preview"}, {"--updates-preview", "--insecure-http-test"}, {"--updates-enable", "--apply", "--cached-windows-updates"}, {"--updates-enable", "--apply", "--cached-windows-updates", "--insecure-http-test"}, {"--updates-disable", "--apply"}, {"--updates-disable", "--apply", "--insecure-http-test"}} {
		called := false
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }); code != 0 || !called {
			t.Fatal(args, code, called)
		}
	}
}

func TestWindowsUpdatesHelpDescribesIndependentScope(t *testing.T) {
	var out bytes.Buffer
	if code := runWith(context.Background(), []string{"--help"}, &out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
		t.Fatal("help reached host")
		return nil, nil
	}); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"--updates-preview", "--updates-enable --apply --cached-windows-updates", "--updates-disable --apply", "No automatic service restart.", windowsupdates.Privacy, windowsupdates.HTTPPrivacy} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("missing update help", want)
		}
	}
}

func TestWindowsUpdatesCanceledInspectionCannotWriteConsent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := updatesOperation(ctx, request{mode: "updates-enable"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		cancel()
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}, func(string, string, bool, bool) (lanclient.WindowsUpdatesConsentResult, error) {
		t.Fatal("canceled lifecycle wrote grant")
		return lanclient.WindowsUpdatesConsentResult{}, nil
	})
	if err == nil {
		t.Fatal("canceled consent lifecycle succeeded")
	}
}
