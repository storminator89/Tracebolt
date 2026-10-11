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

func TestSecurityPostureRequiresOwnedStoppedService(t *testing.T) {
	receipt := windowsservice.Receipt{InstallationID: "fixture-owned-installation", Layout: windowsservice.Layout{EnrollmentRoot: "fixture-enrollment"}}
	for _, mode := range []string{"security-posture-preview", "security-posture-enable", "security-posture-disable"} {
		for _, state := range []windowsservice.State{0, windowsservice.Stopped, windowsservice.Running, windowsservice.StartPending, windowsservice.StopPending} {
			for _, failed := range []bool{false, true} {
				calls, inspections := 0, 0
				_, err := securityPostureOperation(context.Background(), request{mode: mode, insecureHTTP: true}, receipt,
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
					func(path, gotMode string, ack, insecure bool) (lanclient.WindowsSecurityPostureConsentResult, error) {
						calls++
						wantMode := map[string]string{"security-posture-preview": "preview", "security-posture-enable": "enable", "security-posture-disable": "disable"}[mode]
						if path != filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json") || gotMode != wantMode || ack != (wantMode == "enable") || !insecure {
							t.Fatal("consent binding changed")
						}
						return lanclient.WindowsSecurityPostureConsentResult{}, nil
					})
				allowed := !failed && state == windowsservice.Stopped
				if inspections != 1 || (err == nil) != allowed || (calls == 1) != allowed {
					t.Fatal(mode, state, failed, calls, err)
				}
			}
		}
	}
}

func TestSecurityPostureConsentErrorsAndInvalidModes(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{State: windowsservice.Stopped}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsSecurityPostureConsentResult, error) {
		return lanclient.WindowsSecurityPostureConsentResult{}, lanclient.ErrState
	}
	if _, err := securityPostureOperation(context.Background(), request{mode: "security-posture-enable"}, windowsservice.Receipt{}, inspect, configure); !errors.Is(err, lanclient.ErrState) {
		t.Fatal("consent failure hidden", err)
	}
	for _, mode := range []string{"", "install", "enroll", "volumes-enable"} {
		if _, err := securityPostureOperation(context.Background(), request{mode: mode}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			t.Fatal("invalid mode touched service")
			return windowsservice.Snapshot{}, nil
		}, configure); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
}

func TestSecurityPostureConsentNeverConfiguresWithMissingDependencies(t *testing.T) {
	inspect := func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		t.Fatal("invalid invocation reached service")
		return windowsservice.Snapshot{}, nil
	}
	configure := func(string, string, bool, bool) (lanclient.WindowsSecurityPostureConsentResult, error) {
		t.Fatal("invalid invocation reached consent store")
		return lanclient.WindowsSecurityPostureConsentResult{}, nil
	}
	r := request{mode: "security-posture-enable"}
	if _, err := securityPostureOperation(nil, r, windowsservice.Receipt{}, inspect, configure); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := securityPostureOperation(context.Background(), r, windowsservice.Receipt{}, nil, configure); err == nil {
		t.Fatal("nil inspection accepted")
	}
	if _, err := securityPostureOperation(context.Background(), r, windowsservice.Receipt{}, inspect, nil); err == nil {
		t.Fatal("nil configuration accepted")
	}
}

type securityPostureDisclosureWriter struct {
	writes, failAt int
	short          bool
}

func (w *securityPostureDisclosureWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, errors.New("fixture output failure")
	}
	return len(p), nil
}

func TestSecurityPostureDisclosureMustCompleteBeforeDispatch(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, short := range []bool{false, true} {
			out := &securityPostureDisclosureWriter{failAt: failAt, short: short}
			called := false
			code := runWith(context.Background(), []string{"--security-posture-enable", "--apply", "--defender-firewall-posture", "--insecure-http-test"}, out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
				called = true
				return nil, nil
			})
			if code != 1 || called || out.writes != failAt {
				t.Fatal("incomplete startup disclosure reached consent", failAt, short, code, called)
			}
		}
	}
}

func TestSecurityPostureFlagsDoNotAuthorizeAnotherScope(t *testing.T) {
	for _, mode := range []string{"security-posture-preview", "security-posture-enable", "security-posture-disable"} {
		for _, otherScope := range []string{"--basic-readonly", "--windows-inventory", "--application-system-event-headers", "--visible-volumes", "--process-cpu-memory", "--network-endpoints"} {
			args := []string{"--" + mode, otherScope}
			if mode != "security-posture-preview" {
				args = append(args, "--apply")
			}
			if mode == "security-posture-enable" {
				args = append(args, "--defender-firewall-posture")
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

func TestSecurityPostureConsentFlagsExplicitAndBounded(t *testing.T) {
	for _, args := range [][]string{{"--security-posture-enable", "--apply"}, {"--security-posture-enable", "--defender-firewall-posture"}, {"--security-posture-preview", "--apply"}, {"--security-posture-disable", "--apply", "--defender-firewall-posture"}, {"--install", "--apply", "--windows-inventory", "--defender-firewall-posture", "--bootstrap-file=C:\\fixture"}} {
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("invalid flags reached host seam")
			return nil, nil
		}); code != 2 {
			t.Fatal(args, code)
		}
	}
	for _, args := range [][]string{{"--security-posture-preview"}, {"--security-posture-preview", "--insecure-http-test"}, {"--security-posture-enable", "--apply", "--defender-firewall-posture"}, {"--security-posture-enable", "--apply", "--defender-firewall-posture", "--insecure-http-test"}, {"--security-posture-disable", "--apply"}, {"--security-posture-disable", "--apply", "--insecure-http-test"}} {
		called := false
		if code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }); code != 0 || !called {
			t.Fatal(args, code, called)
		}
	}
}
