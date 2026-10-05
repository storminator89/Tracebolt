package main

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/agentinstall"
	"strings"
	"testing"
)

type inertBackend struct{ reads, begins int }

func (b *inertBackend) Inspect(context.Context, agentinstall.Request) (agentinstall.HostFacts, error) {
	b.reads++
	return agentinstall.HostFacts{Linux: true, SystemdAvailable: true, Root: true, AccountCompatible: true, InstallationOwned: true, Profile: "tls"}, nil
}
func (b *inertBackend) Begin(context.Context, agentinstall.Request, agentinstall.Plan) (agentinstall.Transaction, error) {
	b.begins++
	return nil, agentinstall.ErrState
}
func TestCLIIsReadOnlyUnlessExplicitApply(t *testing.T) {
	b := &inertBackend{}
	var out, stderr bytes.Buffer
	if run(context.Background(), []string{"--action", "restart"}, &out, &stderr, b) != 0 || b.begins != 0 || b.reads != 1 {
		t.Fatal("default changed system")
	}
	if run(context.Background(), []string{"--help"}, &out, &stderr, b) != 0 || b.reads != 1 {
		t.Fatal("help inspected system")
	}
	if run(context.Background(), []string{"--action", "restart", "--apply"}, &out, &stderr, b) == 0 || b.begins != 1 {
		t.Fatal("apply failed to use explicit boundary")
	}
}
func TestCLIRejectsSecretAndCommandArgumentsWithoutEcho(t *testing.T) {
	for _, args := range [][]string{{"--invitation", "inert-private-input"}, {"--command", "arbitrary-text"}, {"--reset"}, {"unexpected"}} {
		b := &inertBackend{}
		var out, err bytes.Buffer
		if run(context.Background(), args, &out, &err, b) != 2 || b.reads != 0 || bytes.Contains(err.Bytes(), []byte("inert-private-input")) {
			t.Fatal("invalid argument reached system or transcript")
		}
	}
}

func TestOperationGuidancePreservesPendingAndRecoveryBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		request agentinstall.Request
		result  agentinstall.Result
		err     error
		want    []string
		absent  []string
	}{
		{"dry-run", agentinstall.Request{Action: agentinstall.Install}, agentinstall.Result{Plan: agentinstall.Plan{DryRun: true}}, nil,
			[]string{"Read-only preflight passed", "before deliberately using --apply"}, []string{"Installation committed"}},
		{"pending", agentinstall.Request{Action: agentinstall.Install, PendingService: true}, agentinstall.Result{Committed: true}, nil,
			[]string{"Installation committed", "enabled for startup", "can wait for approval in the background", "first successful report must be checked there separately", "does not establish successful reporting"}, []string{"Reporting is active"}},
		{"ready", agentinstall.Request{Action: agentinstall.Install}, agentinstall.Result{Committed: true}, nil,
			[]string{"Installation committed", "first successful report in the dashboard separately"}, []string{"can wait for approval"}},
		{"upgrade", agentinstall.Request{Action: agentinstall.Upgrade}, agentinstall.Result{Committed: true}, nil,
			[]string{"Upgrade committed", "previous startup enablement", "existing identity were retained"}, []string{"enabled for startup", "approve this device"}},
		{"uninstall", agentinstall.Request{Action: agentinstall.Uninstall}, agentinstall.Result{Committed: true}, nil,
			[]string{"Uninstall committed", "private identity/state were retained"}, []string{"active service process", "actual operating-system reboot"}},
		{"rollback", agentinstall.Request{Action: agentinstall.Install}, agentinstall.Result{RolledBack: true, FailureStage: agentinstall.OpEnroll}, errors.New("private must not leak"),
			[]string{"Stopped while hidden-terminal enrollment", "Owned transaction changes were rolled back", "explicit --resume flow with exactly the same", "systemctl status --no-pager tracebolt-agent.service"}, []string{"Installation committed", "private must not leak"}},
		{"uncertain", agentinstall.Request{Action: agentinstall.Install}, agentinstall.Result{FailureStage: agentinstall.Operation("private must not leak")}, errors.New("untrusted error must not leak"),
			[]string{"Recovery was not confirmed", "do not add --resume", "Preflight or retained installer-state checks"}, []string{"private must not leak", "untrusted error must not leak", "Installation committed"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			reportOperation(c.request, c.result, c.err, &out)
			for _, want := range c.want {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing guidance %q in %s", want, out.String())
				}
			}
			for _, absent := range c.absent {
				if strings.Contains(out.String(), absent) {
					t.Fatalf("misleading or private guidance %q", absent)
				}
			}
		})
	}
}
