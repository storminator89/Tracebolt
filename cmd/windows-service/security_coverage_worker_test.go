package main

import (
	"bytes"
	"context"
	"fmt"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowsservice"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityCoverageWorkerEntryRechecksActualParentBeforeReturning(t *testing.T) {
	raw := fmt.Sprintf(`{"senderBinding":"%s","grantId":"%s","generationId":"sample_%s","collectedAt":"2026-10-10T12:00:00Z"}`, strings.Repeat("a", 64), strings.Repeat("b", 32), strings.Repeat("c", 32))
	for _, mode := range []string{"valid", "before", "after", "replace-parent", "replace-creation", "replace-path", "replace-hash"} {
		t.Run(mode, func(t *testing.T) {
			checks, grants, reads := 0, 0, 0
			var out bytes.Buffer
			identity := windowsservice.ObservationWorkerIdentity{Layout: windowsservice.Layout{EnrollmentRoot: "fixed-fixture"}, ParentProcessID: 10, ParentCreated: 100, ServiceSID: "fixture", ExecutableSHA256: strings.Repeat("1", 64)}
			err := serveSecurityCoverageWorker(context.Background(), strings.NewReader(raw), &out, func(context.Context) (windowsservice.ObservationWorkerIdentity, error) {
				checks++
				if mode == "before" || mode == "after" && checks == 2 {
					return windowsservice.ObservationWorkerIdentity{}, lanclient.ErrState
				}
				value := identity
				if checks == 2 {
					switch mode {
					case "replace-parent":
						value.ParentProcessID++
					case "replace-creation":
						value.ParentCreated++
					case "replace-path":
						value.Layout.EnrollmentRoot = "another"
					case "replace-hash":
						value.ExecutableSHA256 = strings.Repeat("2", 64)
					}
				}
				return value, nil
			}, func(path string, r windowssecuritycoverage.Request) (windowssecuritycoverage.Request, error) {
				grants++
				if path != filepath.Join(identity.Layout.EnrollmentRoot, "agent.json") {
					t.Fatal("IPC supplied path")
				}
				return r, nil
			}, func(_ context.Context, r windowssecuritycoverage.Request) (windowssecuritycoverage.Snapshot, error) {
				reads++
				return windowssecuritycoverage.Empty(r, windowssecuritycoverage.ErrUnavailable.Error()), nil
			})
			if mode == "valid" {
				if err != nil || checks != 2 || grants != 2 || reads != 1 || out.Len() == 0 {
					t.Fatal("valid worker failed", err)
				}
				return
			}
			if err == nil || out.Len() != 0 || mode == "before" && (reads != 0 || grants != 0) || mode != "before" && (reads != 1 || grants != 1) {
				t.Fatal("changed parent emitted snapshot", mode, err, checks, grants, reads)
			}
		})
	}
}
