package main

import (
	"bytes"
	"context"
	"localrmm/internal/agentinstall"
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
