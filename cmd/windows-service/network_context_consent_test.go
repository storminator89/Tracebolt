package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"strings"
	"testing"

	"localrmm/internal/windowsnetworkcontext"
)

func TestNetworkContextCLISeparateAcknowledgementAndDisclosure(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"--network-context-" + mode}
			if mode != "preview" {
				args = append(args, "--apply")
			}
			if mode == "enable" {
				args = append(args, "--routes-interface-counters")
			}
			for _, http := range []bool{false, true} {
				runArgs := append([]string{}, args...)
				if http {
					runArgs = append(runArgs, "--insecure-http-test")
				}
				var out, errout bytes.Buffer
				called := false
				code := runWith(context.Background(), runArgs, &out, &errout, func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
					called = true
					if r.mode != "network-context-"+mode || r.insecureHTTP != http {
						t.Fatal("wrong operation")
					}
					if mode == "enable" || mode == "preview" {
						if !strings.Contains(out.String(), windowsnetworkcontext.Privacy) || http && !strings.Contains(out.String(), windowsnetworkcontext.HTTPPrivacy) {
							t.Fatal("missing pre-dispatch disclosure")
						}
					}
					return nil, nil
				})
				if code != 0 || !called {
					t.Fatal(mode, http, code, errout.String())
				}
			}
		})
	}
	for _, args := range [][]string{{"--network-context-enable", "--apply"}, {"--network-context-enable", "--routes-interface-counters"}, {"--network-context-preview", "--apply"}, {"--network-context-disable", "--apply", "--routes-interface-counters"}, {"--network-context-enable", "--apply", "--routes-interface-counters", "--windows-inventory"}, {"--install", "--apply", "--windows-inventory", "--routes-interface-counters", "--bootstrap-file=C:\\fixture"}} {
		var out bytes.Buffer
		called := false
		code := runWith(context.Background(), args, &out, &out, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil })
		if code != 2 || called {
			t.Fatal("scope flags overlapped", args, code)
		}
	}
}

func TestNetworkContextConsentRequiresStoppedOwnedServiceBeforeState(t *testing.T) {
	for _, state := range []windowsservice.State{windowsservice.Running, windowsservice.Stopped} {
		calls := 0
		result, err := networkContextOperation(context.Background(), request{mode: "network-context-enable"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			return windowsservice.Snapshot{State: state}, nil
		}, func(_ string, mode string, ack, http bool) (lanclient.WindowsNetworkContextConsentResult, error) {
			calls++
			if mode != "enable" || !ack || http {
				t.Fatal("wrong consent route")
			}
			return lanclient.WindowsNetworkContextConsentResult{Scope: windowsnetworkcontext.Scope, Enabled: true}, nil
		})
		if state == windowsservice.Stopped {
			if err != nil || calls != 1 || !result.Enabled {
				t.Fatal("stopped operation rejected")
			}
		} else if err == nil || calls != 0 {
			t.Fatal("running service read/wrote extension state")
		}
	}
	calls := 0
	_, err := networkContextOperation(context.Background(), request{mode: "network-context-preview"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{}, errors.New("unowned")
	}, func(string, string, bool, bool) (lanclient.WindowsNetworkContextConsentResult, error) {
		calls++
		return lanclient.WindowsNetworkContextConsentResult{}, nil
	})
	if err == nil || calls != 0 {
		t.Fatal("unowned service reached state")
	}
}
