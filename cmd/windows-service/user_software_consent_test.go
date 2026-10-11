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

	"localrmm/internal/windowsusersoftware"
)

func TestUserSoftwareCLISeparateAcknowledgementAndDisclosure(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"--user-software-" + mode}
			if mode != "preview" {
				args = append(args, "--apply")
			}
			if mode == "enable" {
				args = append(args, "--selected-user-software")
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
					if r.mode != "user-software-"+mode || r.insecureHTTP != http {
						t.Fatal("wrong operation")
					}
					if mode == "enable" || mode == "preview" {
						if !strings.Contains(out.String(), windowsusersoftware.Privacy) || http && !strings.Contains(out.String(), windowsusersoftware.HTTPPrivacy) {
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
	for _, args := range [][]string{{"--user-software-enable", "--apply"}, {"--user-software-enable", "--selected-user-software"}, {"--user-software-preview", "--apply"}, {"--user-software-disable", "--apply", "--selected-user-software"}, {"--user-software-enable", "--apply", "--selected-user-software", "--windows-inventory"}, {"--install", "--apply", "--windows-inventory", "--selected-user-software", "--bootstrap-file=C:\\fixture"}} {
		var out bytes.Buffer
		called := false
		code := runWith(context.Background(), args, &out, &out, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil })
		if code != 2 || called {
			t.Fatal("scope flags overlapped", args, code)
		}
	}
}

func TestUserSoftwareConsentRequiresStoppedOwnedServiceBeforeState(t *testing.T) {
	for _, state := range []windowsservice.State{windowsservice.Running, windowsservice.Stopped} {
		calls := 0
		result, err := userSoftwareOperation(context.Background(), request{mode: "user-software-enable"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			return windowsservice.Snapshot{State: state}, nil
		}, func(_ string, mode string, ack, http bool) (lanclient.WindowsUserSoftwareConsentResult, error) {
			calls++
			if mode != "enable" || !ack || http {
				t.Fatal("wrong consent route")
			}
			return lanclient.WindowsUserSoftwareConsentResult{Scope: windowsusersoftware.Scope, Enabled: true}, nil
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
	_, err := userSoftwareOperation(context.Background(), request{mode: "user-software-preview"}, windowsservice.Receipt{}, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{}, errors.New("unowned")
	}, func(string, string, bool, bool) (lanclient.WindowsUserSoftwareConsentResult, error) {
		calls++
		return lanclient.WindowsUserSoftwareConsentResult{}, nil
	})
	if err == nil || calls != 0 {
		t.Fatal("unowned service reached state")
	}
}
