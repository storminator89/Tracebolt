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

func TestNetworkRequiresOwnedStoppedService(t *testing.T) {
	receipt := windowsservice.Receipt{InstallationID: "fixture-owned-installation", Layout: windowsservice.Layout{EnrollmentRoot: "fixture-enrollment"}}
	for _, mode := range []string{"network-preview", "network-enable", "network-disable"} {
		for _, state := range []windowsservice.State{0, windowsservice.Stopped, windowsservice.Running, windowsservice.StartPending, windowsservice.StopPending} {
			for _, failed := range []bool{false, true} {
				calls, inspections := 0, 0
				_, err := networkOperation(context.Background(), request{mode: mode, insecureHTTP: true}, receipt,
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
					func(path, gotMode string, ack, insecure bool) (lanclient.WindowsNetworkConsentResult, error) {
						calls++
						wantMode := map[string]string{"network-preview": "preview", "network-enable": "enable", "network-disable": "disable"}[mode]
						if path != filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json") || gotMode != wantMode || ack != (wantMode == "enable") || !insecure {
							t.Fatal("consent binding changed")
						}
						return lanclient.WindowsNetworkConsentResult{}, nil
					})
				allowed := !failed && state == windowsservice.Stopped
				if inspections != 1 || (err == nil) != allowed || (calls == 1) != allowed {
					t.Fatal(mode, state, failed, calls, err)
				}
			}
		}
	}
}

func TestNetworkConsentErrorsAndInvalidModes(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsNetworkConsentResult, error) {
		return lanclient.WindowsNetworkConsentResult{}, lanclient.ErrState
	}
	if _, err := networkOperation(context.Background(), request{mode: "network-enable"}, windowsservice.Receipt{}, inspect, configure); !errors.Is(err, lanclient.ErrState) {
		t.Fatal("consent failure hidden", err)
	}
	for _, mode := range []string{"", "install", "enroll", "volumes-enable"} {
		if _, err := networkOperation(context.Background(), request{mode: mode}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			t.Fatal("invalid mode touched service")
			return windowsservice.Snapshot{}, nil
		}, configure); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
}

func TestNetworkConsentNeverConfiguresWithMissingDependencies(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		t.Fatal("invalid invocation reached service")
		return windowsservice.Snapshot{}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsNetworkConsentResult, error) {
		t.Fatal("invalid invocation reached consent store")
		return lanclient.WindowsNetworkConsentResult{}, nil
	}
	r := request{mode: "network-enable"}
	if _, err := networkOperation(nil, r, windowsservice.Receipt{}, inspect, configure); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := networkOperation(context.Background(), r, windowsservice.Receipt{}, nil, configure); err == nil {
		t.Fatal("nil inspection accepted")
	}
	if _, err := networkOperation(context.Background(), r, windowsservice.Receipt{}, inspect, nil); err == nil {
		t.Fatal("nil configuration accepted")
	}
}

type networkDisclosureWriter struct {
	writes, failAt int
	short          bool
}

func (w *networkDisclosureWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, errors.New("fixture output failure")
	}
	return len(p), nil
}

func TestNetworkDisclosureMustCompleteBeforeDispatch(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, short := range []bool{false, true} {
			out := &networkDisclosureWriter{failAt: failAt, short: short}
			called := false
			code := runWith(context.Background(), []string{"--network-enable", "--apply", "--network-endpoints", "--insecure-http-test"}, out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				called = true
				return nil, nil
			})
			if code != 1 || called || out.writes != failAt {
				t.Fatal("incomplete network disclosure reached consent", failAt, short, code, called)
			}
		}
	}
}

func TestNetworkFlagsDoNotAuthorizeAnotherScope(t *testing.T) {
	for _, mode := range []string{"network-preview", "network-enable", "network-disable"} {
		for _, otherScope := range []string{"--basic-readonly", "--windows-inventory", "--application-system-event-headers", "--visible-volumes", "--process-cpu-memory"} {
			args := []string{"--" + mode, otherScope}
			if mode != "network-preview" {
				args = append(args, "--apply")
			}
			if mode == "network-enable" {
				args = append(args, "--network-endpoints")
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
