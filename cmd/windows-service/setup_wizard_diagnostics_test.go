package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/windowssetup"
)

const setupDiagnosticPrivateMarker = "private-invitation-path-native-error-must-not-escape"

func assertPublicSetupProgress(t *testing.T, messages []string) {
	t.Helper()
	if len(messages) == 0 {
		t.Fatal("missing public setup diagnosis")
	}
	for _, message := range messages {
		if len(message) == 0 || len(message) > 512 {
			t.Fatal("setup progress would be rejected by the native UI")
		}
		if strings.Contains(message, setupDiagnosticPrivateMarker) {
			t.Fatal("private cause escaped through setup progress")
		}
	}
}

func TestSetupWizardFailureOnlyClaimsNoWritesWithProvenOutcome(t *testing.T) {
	privateCompatibility := fmt.Errorf("%s: %w", setupDiagnosticPrivateMarker, windowssetup.ErrCompatibility)
	for _, test := range []struct {
		name       string
		err        error
		before     bool
		compatible bool
	}{
		{"compatibility before writes", &setupWizardOutcomeError{true, privateCompatibility}, true, true},
		{"other failure before writes", &setupWizardOutcomeError{true, errors.New(setupDiagnosticPrivateMarker)}, true, false},
		{"raw compatibility has no phase evidence", windowssetup.ErrCompatibility, false, false},
		{"wrapped raw compatibility has no phase evidence", privateCompatibility, false, false},
		{"compatibility after writes", &setupWizardOutcomeError{false, privateCompatibility}, false, false},
		{"other failure after writes", &setupWizardOutcomeError{false, errors.New(setupDiagnosticPrivateMarker)}, false, false},
		{"unknown failure has no phase evidence", errors.New(setupDiagnosticPrivateMarker), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var messages []string
			setupWizardFailure(test.err, func(message string) { messages = append(messages, message) })
			assertPublicSetupProgress(t, messages)
			text := strings.Join(messages, "\n")
			if strings.HasPrefix(text, "Manager compatibility check failed before installation:") != test.compatible {
				t.Fatal("compatibility diagnosis ignored authoritative mutation phase")
			}
			if test.before {
				if !strings.Contains(text, "No new service, identity or scope grants were created.") {
					t.Fatal("proven pre-installation stop did not describe its boundary")
				}
			} else {
				for _, claim := range []string{"before installation", "No new service", "No installation changes"} {
					if strings.Contains(text, claim) {
						t.Fatal("unknown or post-write failure claimed an unchanged installation")
					}
				}
				if !strings.Contains(text, "Retained state may be incomplete or startup indeterminate.") {
					t.Fatal("uncertain retained state was hidden")
				}
			}
		})
	}
}

func TestSetupWizardCompatibilityDiagnosticFollowsActualMutationBoundary(t *testing.T) {
	for _, failed := range []string{"compatibility", "provision", "install", "package-close", "console-close"} {
		t.Run(failed, func(t *testing.T) {
			var calls, messages []string
			call := func(stage string) error {
				calls = append(calls, stage)
				if stage == failed {
					return fmt.Errorf("%s: %w", setupDiagnosticPrivateMarker, windowssetup.ErrCompatibility)
				}
				return nil
			}
			steps := setupWizardInstallSteps{
				validate:      func([]byte) error { return call("validate") },
				preflight:     func(context.Context) error { return call("preflight") },
				compatibility: func(context.Context, []byte) error { return call("compatibility") },
				console: func() (func() error, error) {
					return func() error { return call("console-close") }, call("console")
				},
				provision: func(context.Context, []byte) (string, func() error, error) {
					return "public-fixture", func() error { return call("package-close") }, call("provision")
				},
				install: func(context.Context, string) error { return call("install") },
			}
			progress := func(message string) { messages = append(messages, message) }
			err := setupWizardInstall(context.Background(), []byte("public-fixture"), steps, progress)
			if !errors.Is(err, windowssetup.ErrCompatibility) {
				t.Fatal("compatibility failure identity lost")
			}
			var outcome *setupWizardOutcomeError
			if !errors.As(err, &outcome) || outcome.beforeMutation != (failed == "compatibility") {
				t.Fatal("mutation phase lost during failure or cleanup")
			}
			wantCalls := []string{"validate", "preflight", "compatibility"}
			if failed != "compatibility" {
				wantCalls = append(wantCalls, "console", "provision")
				if failed != "provision" {
					wantCalls = append(wantCalls, "install")
				}
				wantCalls = append(wantCalls, "package-close", "console-close")
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("unexpected operation ordering: %v", calls)
			}
			setupWizardFailure(err, progress)
			assertPublicSetupProgress(t, messages)
			final := messages[len(messages)-1]
			if strings.HasPrefix(final, "Manager compatibility check failed before installation:") != (failed == "compatibility") {
				t.Fatal("displayed diagnosis contradicts actual completed operations")
			}
		})
	}
}
