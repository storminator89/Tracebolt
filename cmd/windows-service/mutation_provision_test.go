package main

import (
	"context"
	"io"
	"testing"
)

func TestCoordinatedMutationSetupRequiresEveryDistinctApproval(t *testing.T) {
	base := []string{"--msi-manager-offer", "m.json", "--msi-service-file", "m.exe", "--msi-artifact-manifest", "m.manifest.json", "--update-manager-offer", "w.json", "--update-executor-file", "w.exe", "--update-artifact-manifest", "w.manifest.json", "--apply", "--approve", "sha256:fixture", "--acknowledge-coordinated-mutations", "--acknowledge-managed-delivery", "--acknowledge-one-managed-install", "--acknowledge-selected-updates", "--acknowledge-localsystem-risk", "--acknowledge-observer-relay", "--acknowledge-observer-process-query"}
	for _, missing := range []string{"--acknowledge-coordinated-mutations", "--acknowledge-managed-delivery", "--acknowledge-one-managed-install", "--acknowledge-selected-updates", "--acknowledge-localsystem-risk", "--acknowledge-observer-relay", "--acknowledge-observer-process-query"} {
		args := []string{}
		for _, v := range base {
			if v != missing {
				args = append(args, v)
			}
		}
		called := false
		code := runCoordinatedMutationProvision(context.Background(), args, io.Discard, io.Discard, func(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error) {
			called = true
			return coordinatedMutationResult{}, nil
		})
		if code != 2 || called {
			t.Fatalf("missing %s reached provisioning", missing)
		}
	}
	for _, arg := range []string{"--allow-scheduled-updates", "--adopt", "--reset", "--start", "--package-file", "--url", "--shell"} {
		called := false
		code := runCoordinatedMutationProvision(context.Background(), []string{arg}, io.Discard, io.Discard, func(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error) {
			called = true
			return coordinatedMutationResult{}, nil
		})
		if code != 2 || called {
			t.Fatalf("unexpected operation %s admitted", arg)
		}
	}
}
