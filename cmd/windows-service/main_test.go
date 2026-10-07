package main

import (
	"bytes"
	"context"
	"errors"
	"io"
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
