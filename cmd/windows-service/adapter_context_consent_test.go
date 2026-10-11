package main

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"path/filepath"
	"testing"
)

func TestAdapterContextRequiresOwnedStoppedService(t *testing.T) {
	receipt := windowsservice.Receipt{InstallationID: "fixture-owned-installation", Layout: windowsservice.Layout{EnrollmentRoot: "fixture-enrollment"}}
	for _, mode := range []string{"adapter-context-preview", "adapter-context-enable", "adapter-context-disable"} {
		for _, state := range []windowsservice.State{0, windowsservice.Stopped, windowsservice.Running, windowsservice.StartPending, windowsservice.StopPending} {
			for _, failed := range []bool{false, true} {
				calls, inspections := 0, 0
				_, err := adapterContextOperation(context.Background(), request{mode: mode, insecureHTTP: true}, receipt,
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
					func(path, gotMode string, ack, insecure bool) (lanclient.WindowsAdapterContextConsentResult, error) {
						calls++
						wantMode := map[string]string{"adapter-context-preview": "preview", "adapter-context-enable": "enable", "adapter-context-disable": "disable"}[mode]
						if path != filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json") || gotMode != wantMode || ack != (wantMode == "enable") || !insecure {
							t.Fatal("consent binding changed")
						}
						return lanclient.WindowsAdapterContextConsentResult{}, nil
					})
				allowed := !failed && state == windowsservice.Stopped
				if inspections != 1 || (err == nil) != allowed || (calls == 1) != allowed {
					t.Fatal(mode, state, failed, calls, err)
				}
			}
		}
	}
}

func TestAdapterContextConsentErrorsAndInvalidModes(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsAdapterContextConsentResult, error) {
		return lanclient.WindowsAdapterContextConsentResult{}, lanclient.ErrState
	}
	if _, err := adapterContextOperation(context.Background(), request{mode: "adapter-context-enable"}, windowsservice.Receipt{}, inspect, configure); !errors.Is(err, lanclient.ErrState) {
		t.Fatal("consent failure hidden", err)
	}
	for _, mode := range []string{"", "install", "enroll", "volumes-enable"} {
		if _, err := adapterContextOperation(context.Background(), request{mode: mode}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			t.Fatal("invalid mode touched service")
			return windowsservice.Snapshot{}, nil
		}, configure); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
}

func TestAdapterContextConsentNeverConfiguresWithMissingDependencies(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		t.Fatal("invalid invocation reached service")
		return windowsservice.Snapshot{}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsAdapterContextConsentResult, error) {
		t.Fatal("invalid invocation reached consent store")
		return lanclient.WindowsAdapterContextConsentResult{}, nil
	}
	r := request{mode: "adapter-context-enable"}
	if _, err := adapterContextOperation(nil, r, windowsservice.Receipt{}, inspect, configure); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := adapterContextOperation(context.Background(), r, windowsservice.Receipt{}, nil, configure); err == nil {
		t.Fatal("nil inspection accepted")
	}
	if _, err := adapterContextOperation(context.Background(), r, windowsservice.Receipt{}, inspect, nil); err == nil {
		t.Fatal("nil configuration accepted")
	}
}

type adapterContextDisclosureWriter struct {
	writes, failAt int
	short          bool
}

func (w *adapterContextDisclosureWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, errors.New("fixture output failure")
	}
	return len(p), nil
}

func TestAdapterContextDisclosureMustCompleteBeforeDispatch(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, short := range []bool{false, true} {
			out := &adapterContextDisclosureWriter{failAt: failAt, short: short}
			called := false
			code := runWith(context.Background(), []string{"--adapter-context-enable", "--apply", "--adapter-link-dns-gateways", "--insecure-http-test"}, out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				called = true
				return nil, nil
			})
			if code != 1 || called || out.writes != failAt {
				t.Fatal("incomplete startup disclosure reached consent", failAt, short, code, called)
			}
		}
	}
}

func TestAdapterContextFlagsDoNotAuthorizeAnotherScope(t *testing.T) {
	for _, mode := range []string{"adapter-context-preview", "adapter-context-enable", "adapter-context-disable"} {
		for _, otherScope := range []string{"--basic-readonly", "--windows-inventory", "--application-system-event-headers", "--visible-volumes", "--process-cpu-memory", "--network-endpoints"} {
			args := []string{"--" + mode, otherScope}
			if mode != "adapter-context-preview" {
				args = append(args, "--apply")
			}
			if mode == "adapter-context-enable" {
				args = append(args, "--adapter-link-dns-gateways")
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

func TestAdapterContextConsentFlagsExplicitAndBounded(t *testing.T) {
	for _, args := range [][]string{{"--adapter-context-enable", "--apply"}, {"--adapter-context-enable", "--adapter-link-dns-gateways"}, {"--adapter-context-preview", "--apply"}, {"--adapter-context-disable", "--apply", "--adapter-link-dns-gateways"}, {"--install", "--apply", "--windows-inventory", "--adapter-link-dns-gateways", "--bootstrap-file=C:\\fixture"}} {
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("invalid flags reached host seam")
			return nil, nil
		}); code != 2 {
			t.Fatal(args, code)
		}
	}
	for _, args := range [][]string{{"--adapter-context-preview"}, {"--adapter-context-preview", "--insecure-http-test"}, {"--adapter-context-enable", "--apply", "--adapter-link-dns-gateways"}, {"--adapter-context-enable", "--apply", "--adapter-link-dns-gateways", "--insecure-http-test"}, {"--adapter-context-disable", "--apply"}, {"--adapter-context-disable", "--apply", "--insecure-http-test"}} {
		called := false
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }); code != 0 || !called {
			t.Fatal(args, code, called)
		}
	}
}
