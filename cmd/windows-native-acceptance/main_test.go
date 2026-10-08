package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
)

func TestManualAcceptanceCLIRejectsBeforeExecution(t *testing.T) {
	old := compiledSource
	compiledSource = strings.Repeat("a", 40)
	defer func() { compiledSource = old }()
	for _, args := range [][]string{nil, {"--expected-source=" + compiledSource}, {"--approve-services"}, {"--unexpected=private-token"}} {
		var out, stderr bytes.Buffer
		called := false
		code := run(context.Background(), args, &out, &stderr, gate.Environment{}, func(context.Context, *gate.Grant, native.Options) gate.Report { called = true; return gate.Report{} })
		if code != 2 || called || out.Len() != 0 || strings.Contains(stderr.String(), "private-token") {
			t.Fatal("unguarded CLI executed or leaked inputs")
		}
	}
}
func TestAutomaticEventCannotRunApprovedLookingFlags(t *testing.T) {
	old := compiledSource
	compiledSource = strings.Repeat("a", 40)
	defer func() { compiledSource = old }()
	args := []string{"--expected-source=" + compiledSource, "--approve-services", "--approve-identity", "--approve-app-acls", "--approve-loopback", "--approve-cleanup", "--collection-profile=basic-readonly-v1", "--transport-profile=tls", "--service-artifact=fixture.exe", "--service-sha256=" + strings.Repeat("b", 64), "--controller-artifact=fixture-controller.exe", "--controller-sha256=" + strings.Repeat("c", 64)}
	env := gate.Environment{Event: "push", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: compiledSource, RunID: "42"}
	var out, stderr bytes.Buffer
	called := false
	if run(context.Background(), args, &out, &stderr, env, func(context.Context, *gate.Grant, native.Options) gate.Report { called = true; return gate.Report{} }) != 2 || called {
		t.Fatal("automatic event reached native executor")
	}
}

func TestExpandedCLIRequiresFourFreshFlags(t *testing.T) {
	old := compiledSource
	compiledSource = strings.Repeat("a", 40)
	defer func() { compiledSource = old }()
	for mask := 0; mask < 16; mask++ {
		args := []string{"--expected-source=" + compiledSource, "--approve-services", "--approve-identity", "--approve-app-acls", "--approve-loopback", "--approve-cleanup", "--approve-inventory-metadata", "--collection-profile=windows-inventory-v1", "--transport-profile=tls", "--service-artifact=inert.exe", "--service-sha256=" + strings.Repeat("b", 64), "--controller-artifact=inert-controller.exe", "--controller-sha256=" + strings.Repeat("c", 64)}
		for bit, flag := range []string{"--approve-event-headers", "--approve-visible-volumes", "--approve-process-metrics", "--approve-network-endpoints"} {
			if mask&(1<<bit) != 0 {
				args = append(args, flag)
			}
		}
		env := gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: compiledSource, RunID: "42"}
		var out, stderr bytes.Buffer
		called := false
		code := run(context.Background(), args, &out, &stderr, env, func(_ context.Context, g *gate.Grant, o native.Options) gate.Report {
			called = true
			if o.Expanded != (mask == 15) || g.ExtensionsApproved() != o.Expanded {
				t.Fatal("flags not bound")
			}
			r := gate.NewSelectedReport(compiledSource, g.Selection())
			if o.Expanded {
				z := profile.ZeroExtensionObservation()
				r.Extensions = &z
				r.Schema = gate.ExpandedSchema
			}
			return r
		})
		admitted := mask == 0 || mask == 15
		if called != admitted || !admitted && code != 2 || admitted && code != 1 {
			t.Fatal("CLI extension admission changed")
		}
	}
}
