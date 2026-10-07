package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"localrmm/internal/windowsservice"
)

func TestCLIFinitePhaseReasonDoesNotEchoCause(t *testing.T) {
	cause := errors.New("PRIVATE invitation token, C:\\secret-path, hostname")
	var out, stderr bytes.Buffer
	op := func(context.Context, request, io.Writer, io.Writer) (any, error) {
		return nil, windowsservice.Mark(windowsservice.PhasePendingApproval, windowsservice.ReasonApprovalExpired, cause)
	}
	if runWith(context.Background(), []string{"--run-service"}, &out, &stderr, op) != 1 || out.Len() != 0 {
		t.Fatal("failed fixture dispatch result")
	}
	text := stderr.String()
	if !strings.Contains(text, "phase=pending_approval reason=approval_expired serviceSpecificExitCode=") || strings.Contains(text, "PRIVATE") || strings.Contains(text, "secret-path") || strings.Contains(text, "hostname") {
		t.Fatal("diagnostic lost safe category or leaked raw cause")
	}
}
func TestSetupRuntimeReadPreflightStopsBeforeJournalOrClaim(t *testing.T) {
	f := &setupFixture{}
	s := f.operations()
	s.plan = func(context.Context) (windowsservice.InstallPlan, error) {
		return windowsservice.InstallPlan{}, windowsservice.ErrRuntimeReadAccess
	}
	_, err := setup(context.Background(), "fixture", s)
	d := windowsservice.Diagnostic(err)
	if d.Reason != windowsservice.ReasonRuntimeReadDenied || d.Phase != windowsservice.PhaseRuntimeInstallation || len(f.steps) != 0 {
		t.Fatal("failed read preflight reached installation or claim")
	}
}
func TestSetupFiniteFailurePhases(t *testing.T) {
	cases := []struct {
		stage string
		phase windowsservice.Phase
	}{{"validate-bootstrap", windowsservice.PhaseBootstrap}, {"create-journal", windowsservice.PhaseReceipt}, {"intent.json", windowsservice.PhaseReceipt}, {"apply", windowsservice.PhaseSetup}, {"prepare", windowsservice.PhaseRetainedState}, {"enroll", windowsservice.PhaseEnrollment}}
	for _, c := range cases {
		f := &setupFixture{fail: c.stage}
		_, err := setup(context.Background(), "fixture", f.operations())
		d := windowsservice.Diagnostic(err)
		if d.Phase != c.phase || d.ServiceCode == 0 {
			t.Fatal("setup failure phase not retained")
		}
	}
}

func TestSetupRechecksRuntimeReadBeforeClaimAfterPreparation(t *testing.T) {
	f := &setupFixture{}
	s := f.operations()
	s.verifyOwned = func(context.Context, windowsservice.Receipt) error { return windowsservice.ErrRuntimeReadAccess }
	_, err := setup(context.Background(), "fixture", s)
	if windowsservice.Diagnostic(err).Reason != windowsservice.ReasonRuntimeReadDenied {
		t.Fatal("preclaim read denial category lost")
	}
	for _, step := range f.steps {
		if step == "enroll" || step == "start" {
			t.Fatal("preclaim denial still used invitation or started service")
		}
	}
	if !f.prepared {
		t.Fatal("fixture did not reach post-prepare preflight")
	}
}
