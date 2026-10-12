package main

import (
	"context"
	"io"
	"localrmm/internal/windowsaction"
	"testing"
)

func TestActionProvisionRequiresSeparateUncheckedExactConsent(t *testing.T) {
	base := []string{"--policy-file", "unread-policy", "--broker-file", "unread-image", "--artifact-manifest", "unread-manifest"}
	for _, extra := range [][]string{{"--apply"}, {"--apply", "--approve", "sha256:review"}, {"--acknowledge-service-control"}, {"--approve", "sha256:review"}, {"--apply", "--approve", "sha256:review", "--acknowledge-service-control", "--start"}, {"--apply", "--approve", "sha256:review", "--acknowledge-service-control", "--twelve-read-admin-scopes"}, {"--shell", "powershell"}} {
		calls := 0
		args := append(append([]string{}, base...), extra...)
		code := runActionProvision(context.Background(), args, io.Discard, io.Discard, func(context.Context, actionProvisionInput) (windowsaction.ProvisionPlan, error) {
			calls++
			return windowsaction.ProvisionPlan{}, nil
		})
		if code != 2 || calls != 0 {
			t.Fatal("invalid consent reached input or native work", extra, code, calls)
		}
	}
}
func TestActionProvisionCannotMixWithReadAdminModes(t *testing.T) {
	for _, args := range [][]string{{"--read-admin-preview", "--service-actions-provision"}, {"--service-actions-provision", "--policy-file", "unread", "--read-admin-preview"}, {"--service-actions-setup", "--policy-file", "unread", "--service-actions-provision"}} {
		if run(context.Background(), args, io.Discard, io.Discard) != 2 {
			t.Fatal("mixed mode admitted", args)
		}
	}
}
