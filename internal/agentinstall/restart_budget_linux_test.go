//go:build linux

package agentinstall

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// All effects below use the existing disposable adapter. No systemd, account
// command, collector, listener or network is executed.
func TestLinuxAdapterExplicitRestartResetsExhaustedStartBudget(t *testing.T) {
	r, b, events := installerHostFixture(t)
	original := b.host.run
	starts, resets := 0, 0
	b.host.run = func(ctx context.Context, path string, args []string, a *accountRecord, interactive bool) error {
		if filepath.Base(path) == "systemctl" && len(args) == 2 {
			if args[0] == "reset-failed" {
				if args[1] != UnitName {
					t.Fatal("reset escaped owned unit")
				}
				resets++
				starts = 0
			}
			if args[0] == "start" {
				starts++
				if starts > 5 {
					return ErrOperation
				}
			}
		}
		return original(ctx, path, args, a, interactive)
	}
	if out, err := Execute(context.Background(), r, b); err != nil || !out.Committed || starts != 1 || resets != 0 {
		t.Fatal("initial install unexpectedly reset its budget", err, out.FailureStage)
	}
	// Four real onboarding restore paths are independently composed in
	// deploy/onboarding/test_restart_budget.py: inventory, journal setup,
	// journal readback, and socket setup. Model their shared systemd counter.
	for i := 0; i < 4; i++ {
		if b.host.run(context.Background(), b.host.path(systemctlPath), []string{"stop", UnitName}, nil, false) != nil {
			t.Fatal("onboarding stop")
		}
		if b.host.run(context.Background(), b.host.path(systemctlPath), []string{"start", UnitName}, nil, false) != nil {
			t.Fatal("onboarding budget")
		}
	}
	if b.host.run(context.Background(), b.host.path(systemctlPath), []string{"stop", UnitName}, nil, false) != nil {
		t.Fatal("old restart stop")
	}
	if starts != 5 || b.host.run(context.Background(), b.host.path(systemctlPath), []string{"start", UnitName}, nil, false) == nil {
		t.Fatal("old sixth start did not reproduce rate-limit rejection")
	}
	n := len(*events)
	out, err := Execute(context.Background(), Request{Action: Restart, Apply: true}, b)
	if err != nil || !out.Committed || starts != 1 || resets != 1 {
		t.Fatal("explicit restart did not reopen only its own budget", err, out.FailureStage)
	}
	sequence := strings.Join((*events)[n:], "\n")
	validate := strings.Index(sequence, "lan-agent:--config ")
	reset := strings.Index(sequence, "systemctl:reset-failed "+UnitName)
	start := strings.Index(sequence, "systemctl:start "+UnitName)
	if validate < 0 || reset <= validate || start <= reset {
		t.Fatal("reset escaped stopped validation", sequence)
	}
	// The immediately following revoke restore is now the second start.
	if b.host.run(context.Background(), b.host.path(systemctlPath), []string{"stop", UnitName}, nil, false) != nil {
		t.Fatal("revoke stop")
	}
	if b.host.run(context.Background(), b.host.path(systemctlPath), []string{"start", UnitName}, nil, false) != nil || starts != 2 {
		t.Fatal("revoke restore lacks a start budget")
	}
	if !strings.Contains(Unit, "StartLimitIntervalSec=300s\nStartLimitBurst=5\n") {
		t.Fatal("automatic crash limit changed")
	}
}

func TestLinuxRestartResetRequiresStoppedValidatedRestart(t *testing.T) {
	for _, tc := range []struct {
		action             Action
		stopped, validated bool
	}{
		{Install, true, true}, {Upgrade, true, true}, {Uninstall, true, true},
		{Restart, false, true}, {Restart, true, false},
	} {
		calls := 0
		tx := &linuxTransaction{h: &linuxHost{run: func(context.Context, string, []string, *accountRecord, bool) error { calls++; return nil }}, r: Request{Action: tc.action}, stopped: tc.stopped, validated: tc.validated, j: installJournal{Operation: OpResetRestartState, Phase: "intent"}}
		if tx.Apply(context.Background(), OpResetRestartState, tx.r) == nil || calls != 0 {
			t.Fatal("unguarded reset", tc)
		}
	}
	calls := []string{}
	tx := &linuxTransaction{h: &linuxHost{run: func(_ context.Context, _ string, args []string, _ *accountRecord, _ bool) error {
		calls = append(calls, strings.Join(args, " "))
		return ErrOperation
	}}, r: Request{Action: Restart}, stopped: true, validated: true, j: installJournal{Operation: OpResetRestartState, Phase: "intent"}}
	if tx.Apply(context.Background(), OpResetRestartState, tx.r) == nil || !reflect.DeepEqual(calls, []string{"reset-failed " + UnitName}) {
		t.Fatal("reset failure ignored")
	}
}

func TestRestartResetFailuresNeverReachStart(t *testing.T) {
	for _, stage := range []string{"before:" + string(OpStop), "apply:" + string(OpStop), "apply:" + string(OpValidate), "done:" + string(OpValidate), "apply:" + string(OpResetRestartState)} {
		r, b := installFixture()
		r.Action = Restart
		b.facts.InstallationOwned = true
		b.fail = stage
		out, err := Execute(context.Background(), r, b)
		joined := strings.Join(b.events, "\n")
		if !errors.Is(err, ErrOperation) || out.Committed || strings.Contains(joined, "apply:"+string(OpStart)) {
			t.Fatal("failed restart continued", stage)
		}
		if stage != "apply:"+string(OpResetRestartState) && strings.Contains(joined, "apply:"+string(OpResetRestartState)) {
			t.Fatal("reset before successful validation", stage)
		}
	}
	r, b := installFixture()
	r.Action = Restart
	if _, err := Execute(context.Background(), r, b); err == nil || b.begun != 0 {
		t.Fatal("foreign installation reset")
	}
	r, b = installFixture()
	r.Action = Restart
	r.Apply = false
	b.facts.InstallationOwned = true
	if out, err := Execute(context.Background(), r, b); err != nil || !out.Plan.DryRun || b.begun != 0 {
		t.Fatal("dry run reset")
	}
}
