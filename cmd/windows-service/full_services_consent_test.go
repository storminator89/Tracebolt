package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"localrmm/internal/windowsfullservices"
)

func TestFullServicesCLISeparateAcknowledgementAndDisclosure(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"--full-services-" + mode}
			if mode != "preview" {
				args = append(args, "--apply")
			}
			if mode == "enable" {
				args = append(args, "--complete-win32-services")
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
					if r.mode != "full-services-"+mode || r.insecureHTTP != http {
						t.Fatal("wrong operation")
					}
					if mode == "enable" || mode == "preview" {
						if !strings.Contains(out.String(), windowsfullservices.Privacy) || http && !strings.Contains(out.String(), windowsfullservices.HTTPPrivacy) {
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
	for _, args := range [][]string{{"--full-services-enable", "--apply"}, {"--full-services-enable", "--complete-win32-services"}, {"--full-services-preview", "--apply"}, {"--full-services-disable", "--apply", "--complete-win32-services"}, {"--full-services-enable", "--apply", "--complete-win32-services", "--windows-inventory"}, {"--install", "--apply", "--windows-inventory", "--complete-win32-services", "--bootstrap-file=C:\\fixture"}} {
		var out bytes.Buffer
		called := false
		code := runWith(context.Background(), args, &out, &out, func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil })
		if code != 2 || called {
			t.Fatal("scope flags overlapped", args, code)
		}
	}
}
