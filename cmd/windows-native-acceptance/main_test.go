package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
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
