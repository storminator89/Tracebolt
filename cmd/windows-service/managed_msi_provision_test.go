package main

import (
	"context"
	"io"
	"testing"
)

func TestManagedMSISetupNeedsEveryFreshLocalScope(t *testing.T) {
	base := []string{"--manager-offer", "fixture.json", "--service-file", "fixture.exe", "--artifact-manifest", "fixture.manifest.json", "--apply", "--approve", "sha256:fixture", "--acknowledge-managed-delivery", "--acknowledge-one-managed-install", "--acknowledge-localsystem-risk", "--acknowledge-observer-relay", "--acknowledge-observer-process-query"}
	for _, missing := range []string{"--acknowledge-managed-delivery", "--acknowledge-one-managed-install", "--acknowledge-localsystem-risk", "--acknowledge-observer-relay", "--acknowledge-observer-process-query"} {
		t.Run(missing, func(t *testing.T) {
			args := []string{}
			for _, a := range base {
				if a != missing {
					args = append(args, a)
				}
			}
			called := false
			code := runManagedMSIProvision(context.Background(), args, io.Discard, io.Discard, func(context.Context, managedMSIInput) (managedMSIResult, error) {
				called = true
				return managedMSIResult{}, nil
			})
			if code != 2 || called {
				t.Fatal("missing scope reached native setup", missing, code)
			}
		})
	}
}
func TestManagedMSISetupRejectsPackagePathShellAndImplicitActivation(t *testing.T) {
	for _, arg := range []string{"--package-file", "--url", "--shell", "--start", "--run-foreground", "--acknowledge-prepared-msi"} {
		called := false
		code := runManagedMSIProvision(context.Background(), []string{arg, "fixture"}, io.Discard, io.Discard, func(context.Context, managedMSIInput) (managedMSIResult, error) {
			called = true
			return managedMSIResult{}, nil
		})
		if code != 2 || called {
			t.Fatal("extra operation admitted", arg, code)
		}
	}
}
