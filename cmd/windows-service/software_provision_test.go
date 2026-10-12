package main

import (
	"context"
	"io"
	"testing"
)

func TestPreparedMSISetupRequiresEveryDistinctApproval(t *testing.T) {
	base := []string{"--manager-offer", "x", "--executor-file", "y", "--artifact-manifest", "z", "--package-file", "p", "--package-review", "r"}
	approvals := []string{"--apply", "--approve", "sha256:x", "--acknowledge-prepared-msi", "--acknowledge-observer-relay", "--acknowledge-observer-process-query", "--acknowledge-package-risk-and-terms", "--acknowledge-package-native-acceptance"}
	for _, missing := range []string{"--acknowledge-prepared-msi", "--acknowledge-observer-relay", "--acknowledge-observer-process-query", "--acknowledge-package-risk-and-terms", "--acknowledge-package-native-acceptance"} {
		args := append([]string{}, base...)
		for _, a := range approvals {
			if a != missing {
				args = append(args, a)
			}
		}
		called := false
		code := runSoftwareProvision(context.Background(), args, io.Discard, io.Discard, func(context.Context, softwareProvisionInput) (softwareProvisionResult, error) {
			called = true
			return softwareProvisionResult{}, nil
		})
		if code != 2 || called {
			t.Fatal("missing independent acknowledgment admitted", missing, code)
		}
	}
	for _, foreign := range []string{"--acknowledge-selected-updates", "--allow-scheduled-updates", "--acknowledge-service-control", "--read-admin", "--insecure-http-test", "--remove", "--repair", "--properties"} {
		called := false
		args := append(append([]string{}, base...), foreign)
		code := runSoftwareProvision(context.Background(), args, io.Discard, io.Discard, func(context.Context, softwareProvisionInput) (softwareProvisionResult, error) {
			called = true
			return softwareProvisionResult{}, nil
		})
		if code != 2 || called {
			t.Fatal("foreign authority/operation admitted", foreign, code)
		}
	}
}
