package main

import (
	"context"
	"io"
	"localrmm/internal/windowsupdatesetup"
	"testing"
)

func TestSelectedUpdateSetupRequiresIndependentApproval(t *testing.T) {
	for _, args := range [][]string{{}, {"--manager-offer", "x", "--executor-file", "y", "--artifact-manifest", "z", "--apply"}, {"--manager-offer", "x", "--executor-file", "y", "--artifact-manifest", "z", "--apply", "--approve", "sha256:x", "--acknowledge-selected-updates"}, {"--manager-offer", "x", "--executor-file", "y", "--artifact-manifest", "z", "--insecure-http-test"}, {"--read-admin"}, {"--acknowledge-service-control"}, {"--run-foreground"}} {
		called := false
		n := runUpdateProvision(context.Background(), args, io.Discard, io.Discard, func(context.Context, updateProvisionInput) (updateProvisionResult, error) {
			called = true
			return updateProvisionResult{}, nil
		})
		if n != 2 || called {
			t.Fatal("missing distinct consent admitted", args, n)
		}
	}
	for _, args := range [][]string{{"--apply"}, {"--approve", "x"}, {"--apply", "--approve", "x"}, {"--acknowledge-remove-selected-updates"}} {
		called := false
		n := runUpdateRemove(context.Background(), args, io.Discard, io.Discard, func(context.Context, bool, string) (windowsupdatesetup.RemovalPlan, error) {
			called = true
			return windowsupdatesetup.RemovalPlan{}, nil
		})
		if n != 2 || called {
			t.Fatal("removal inferred approval", args)
		}
	}
}

func TestScheduledUpdateSetupRequiresSeparateFreshFlagAndAcknowledgement(t *testing.T) {
	base := []string{"--manager-offer", "x", "--executor-file", "y", "--artifact-manifest", "z"}
	apply := []string{"--apply", "--approve", "sha256:x", "--acknowledge-selected-updates", "--acknowledge-observer-relay", "--acknowledge-observer-process-query"}
	for _, extra := range [][]string{{"--acknowledge-scheduled-updates"}, {"--allow-scheduled-updates", "--acknowledge-scheduled-updates"}, append(append([]string{}, apply...), "--allow-scheduled-updates"), append(append([]string{}, apply...), "--acknowledge-scheduled-updates")} {
		called := false
		code := runUpdateProvision(context.Background(), append(append([]string{}, base...), extra...), io.Discard, io.Discard, func(context.Context, updateProvisionInput) (updateProvisionResult, error) {
			called = true
			return updateProvisionResult{}, nil
		})
		if code != 2 || called {
			t.Fatal("scheduled setup inferred local acknowledgement", extra, code)
		}
	}
}
