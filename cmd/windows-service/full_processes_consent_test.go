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

	"localrmm/internal/windowsfullprocesses"
)

func TestFullProcessesCLISeparateAcknowledgementAndDisclosure(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"--full-processes-" + mode}
			if mode != "preview" {
				args = append(args, "--apply")
			}
			if mode == "enable" {
				args = append(args, "--complete-process-inventory")
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
					if r.mode != "full-processes-"+mode || r.insecureHTTP != http {
						t.Fatal("wrong operation")
					}
					if mode == "enable" || mode == "preview" {
						if !strings.Contains(out.String(), windowsfullprocesses.Privacy) || http && !strings.Contains(out.String(), windowsfullprocesses.HTTPPrivacy) {
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
	for _, args := range [][]string{{"--full-processes-enable", "--apply"}, {"--full-processes-enable", "--complete-process-inventory"}, {"--full-processes-preview", "--apply"}, {"--full-processes-disable", "--apply", "--complete-process-inventory"}, {"--full-processes-enable", "--apply", "--complete-process-inventory", "--windows-inventory"}, {"--install", "--apply", "--windows-inventory", "--complete-process-inventory", "--bootstrap-file=C:\\fixture"}} {
		var out bytes.Buffer
		called := false
		code := runWith(context.Background(), args, &out, &out, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil })
		if code != 2 || called {
			t.Fatal("scope flags overlapped", args, code)
		}
	}
}

func TestFullProcessesConsentRequiresStoppedOwnedServiceBeforeState(t *testing.T) {
	for _, state := range []windowsservice.State{windowsservice.Running, windowsservice.Stopped} {
		calls := 0
		result, err := fullProcessesOperation(context.Background(), request{mode: "full-processes-enable"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			return windowsservice.Snapshot{State: state}, nil
		}, func(_ string, mode string, ack, http bool) (lanclient.WindowsFullProcessesConsentResult, error) {
			calls++
			if mode != "enable" || !ack || http {
				t.Fatal("wrong consent route")
			}
			return lanclient.WindowsFullProcessesConsentResult{Scope: windowsfullprocesses.Scope, Enabled: true}, nil
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
	_, err := fullProcessesOperation(context.Background(), request{mode: "full-processes-preview"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{}, errors.New("unowned")
	}, func(string, string, bool, bool) (lanclient.WindowsFullProcessesConsentResult, error) {
		calls++
		return lanclient.WindowsFullProcessesConsentResult{}, nil
	})
	if err == nil || calls != 0 {
		t.Fatal("unowned service reached state")
	}
}
