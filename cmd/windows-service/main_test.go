package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/windowsvolumes"
	"strings"
	"testing"
)

func TestWindowsLifecycleFlagsFailBeforeAnyOperation(t *testing.T) {
	cases := [][]string{nil, {"--install"}, {"--install", "--apply"}, {"--install", "--apply", "--basic-readonly"}, {"--start"}, {"--enroll", "--apply"}, {"--plan", "--apply"}, {"--run-service", "--apply"}, {"--stop", "--apply", "--basic-readonly"}, {"--plan", "--inspect"}, {"--plan", "secret-position"}, {"--shell=private-secret"}, {"--plan", "--bootstrap-file=private-path"}}
	for _, args := range cases {
		var out, stderr bytes.Buffer
		called := false
		op := func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }
		if runWith(context.Background(), args, &out, &stderr, op) != 2 || called || out.Len() != 0 {
			t.Fatal("invalid or unapproved operation reached backend")
		}
		if strings.Contains(stderr.String(), "private-") || strings.Contains(stderr.String(), "secret-position") {
			t.Fatal("input leaked into diagnostics")
		}
	}
}
func TestWindowsLifecycleApprovedModesDispatchExactlyOnce(t *testing.T) {
	cases := []struct {
		args []string
		mode string
	}{{[]string{"--plan"}, "plan"}, {[]string{"--inspect"}, "inspect"}, {[]string{"--install", "--apply", "--basic-readonly", "--bootstrap-file=C:\\Fixture\\bootstrap.json"}, "install"}, {[]string{"--enroll", "--apply", "--basic-readonly"}, "enroll"}, {[]string{"--start", "--apply"}, "start"}, {[]string{"--stop", "--apply"}, "stop"}, {[]string{"--uninstall", "--apply"}, "uninstall"}, {[]string{"--run-service"}, "run-service"}}
	for _, c := range cases {
		var out, stderr bytes.Buffer
		calls := 0
		op := func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
			calls++
			if r.mode != c.mode {
				t.Fatal("wrong operation")
			}
			return struct {
				Status string `json:"status"`
			}{"fixture"}, nil
		}
		if runWith(context.Background(), c.args, &out, &stderr, op) != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(out.String(), "fixture") {
			t.Fatal("approved fixture dispatch failed")
		}
	}
}
func TestWindowsLifecycleHelpAndErrorsAreInertAndSanitized(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		var out, stderr bytes.Buffer
		op := func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("help dispatched")
			return nil, nil
		}
		if runWith(context.Background(), []string{arg}, &out, &stderr, op) != 0 {
			t.Fatal("help failed")
		}
		if !strings.Contains(out.String(), "No Windows installation/reboot acceptance") {
			t.Fatal("acceptance boundary absent")
		}
	}
	var out, stderr bytes.Buffer
	op := func(context.Context, request, io.Writer, io.Writer) (any, error) {
		return nil, errors.New("private-credential-path")
	}
	if runWith(context.Background(), []string{"--inspect"}, &out, &stderr, op) != 1 || strings.Contains(stderr.String(), "private-credential-path") || out.Len() != 0 {
		t.Fatal("native error leaked")
	}
}

type shortOutput struct{}

func (shortOutput) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestWindowsLifecycleShortWriteFails(t *testing.T) {
	op := func(context.Context, request, io.Writer, io.Writer) (any, error) { return "fixture", nil }
	if runWith(context.Background(), []string{"--plan"}, shortOutput{}, io.Discard, op) != 1 {
		t.Fatal("short write accepted")
	}
}

func TestWindowsInventoryConsentDispatchAndConflicts(t *testing.T) {
	for _, mode := range []string{"install", "enroll"} {
		args := []string{"--" + mode, "--apply", "--windows-inventory"}
		if mode == "install" {
			args = append(args, "--bootstrap-file=C:\\Fixture\\bootstrap.json")
		}
		var out, stderr bytes.Buffer
		calls := 0
		op := func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
			calls++
			if r.collectionProfile != "windows-inventory-v1" {
				t.Fatal("scope not forwarded")
			}
			if !strings.Contains(out.String(), "IP addresses") || !strings.Contains(out.String(), "event content") {
				t.Fatal("scope not disclosed before dispatch")
			}
			return nil, nil
		}
		if runWith(context.Background(), args, &out, &stderr, op) != 0 || calls != 1 {
			t.Fatal("consented Windows mode rejected")
		}
		args = append(args, "--basic-readonly")
		if runWith(context.Background(), args, io.Discard, io.Discard, op) != 2 || calls != 1 {
			t.Fatal("conflicting scope reached operation")
		}
	}
	for _, mode := range []string{"plan", "inspect", "run-service", "start", "stop", "uninstall"} {
		args := []string{"--" + mode, "--windows-inventory"}
		if mode == "start" || mode == "stop" || mode == "uninstall" {
			args = append(args, "--apply")
		}
		op := func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("runtime scope override reached backend")
			return nil, nil
		}
		if runWith(context.Background(), args, io.Discard, io.Discard, op) != 2 {
			t.Fatal("runtime scope override accepted")
		}
	}
}

func TestWindowsInventoryHTTPFlagDisclosesBeforeDispatch(t *testing.T) {
	var out, stderr bytes.Buffer
	called := false
	op := func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
		called = true
		if !r.insecureHTTP || r.collectionProfile != "windows-inventory-v1" || !strings.Contains(out.String(), "plaintext") || !strings.Contains(out.String(), "manager responses can be forged") {
			t.Fatal("HTTP disclosure or acknowledgement missing")
		}
		return nil, nil
	}
	if runWith(context.Background(), []string{"--enroll", "--apply", "--windows-inventory", "--insecure-http-test"}, &out, &stderr, op) != 0 || !called {
		t.Fatal("explicit test mode rejected")
	}
	for _, args := range [][]string{{"--enroll", "--apply", "--basic-readonly", "--insecure-http-test"}, {"--run-service", "--insecure-http-test"}, {"--start", "--apply", "--insecure-http-test"}} {
		called = false
		if runWith(context.Background(), args, io.Discard, io.Discard, op) != 2 || called {
			t.Fatal("HTTP flag widened existing scope")
		}
	}
}

func TestEventConsentFlagsExplicitAndBounded(t *testing.T) {
	for _, args := range [][]string{{"--events-enable", "--apply"}, {"--events-enable", "--application-system-event-headers"}, {"--events-preview", "--apply"}, {"--events-disable", "--apply", "--application-system-event-headers"}, {"--install", "--apply", "--windows-inventory", "--application-system-event-headers", "--bootstrap-file=C:\\fixture"}} {
		called := false
		op := func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }
		if runWith(context.Background(), args, io.Discard, io.Discard, op) != 2 || called {
			t.Fatal("invalid event grant reached backend")
		}
	}
	for _, args := range [][]string{{"--events-preview"}, {"--events-enable", "--apply", "--application-system-event-headers"}, {"--events-enable", "--apply", "--application-system-event-headers", "--insecure-http-test"}, {"--events-disable", "--apply"}} {
		var out bytes.Buffer
		called := false
		op := func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
			called = true
			if r.mode == "events-enable" && !strings.Contains(out.String(), "Application and System event headers") {
				t.Fatal("scope not disclosed")
			}
			return nil, nil
		}
		if runWith(context.Background(), args, &out, io.Discard, op) != 0 || !called {
			t.Fatal("valid fixture dispatch rejected")
		}
	}
}

func TestVolumeConsentFlagsExplicitAndBounded(t *testing.T) {
	for _, args := range [][]string{{"--volumes-enable", "--apply"}, {"--volumes-enable", "--visible-volumes"}, {"--volumes-preview", "--apply"}, {"--volumes-disable", "--apply", "--visible-volumes"}, {"--volumes-enable", "--apply", "--visible-volumes", "--application-system-event-headers"}, {"--install", "--apply", "--windows-inventory", "--visible-volumes", "--bootstrap-file=C:\\fixture"}} {
		called := false
		op := func(context.Context, request, io.Writer, io.Writer) (any, error) { called = true; return nil, nil }
		if runWith(context.Background(), args, io.Discard, io.Discard, op) != 2 || called {
			t.Fatal("invalid volume grant reached backend")
		}
	}
	for _, args := range [][]string{{"--volumes-preview"}, {"--volumes-preview", "--insecure-http-test"}, {"--volumes-enable", "--apply", "--visible-volumes"}, {"--volumes-enable", "--apply", "--visible-volumes", "--insecure-http-test"}, {"--volumes-disable", "--apply"}, {"--volumes-disable", "--apply", "--insecure-http-test"}} {
		var out bytes.Buffer
		called := false
		op := func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
			called = true
			if r.mode == "volumes-enable" && !strings.Contains(out.String(), windowsvolumes.Privacy) {
				t.Fatal("scope not disclosed")
			}
			if r.insecureHTTP && !strings.Contains(out.String(), "plaintext") {
				t.Fatal("HTTP warning missing")
			}
			return nil, nil
		}
		if runWith(context.Background(), args, &out, io.Discard, op) != 0 || !called {
			t.Fatal("valid fixture volume dispatch rejected", args)
		}
	}
}
