package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/agentloop"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"path/filepath"
	"time"
)

type pendingServiceOptions struct {
	BootstrapPath, StateDirectory, ConfigPath, Identity string
	InsecureHTTPTest                                    bool
	Interval                                            time.Duration
}
type pendingServiceHooks struct {
	identity     func(string) bool
	load         func(string) (enrollmentclient.Bootstrap, error)
	inspect      func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error)
	resume       func(context.Context, enrollmentclient.Bootstrap, string, bool, func(enrollmentclient.Progress) error) (enrollmentclient.Result, error)
	markReady    func(enrollmentclient.Bootstrap, string, bool) (enrollmentclient.ServiceState, error)
	stopDeadline func(enrollmentclient.Bootstrap, string, bool) error
	sender       func(context.Context, string, time.Duration, io.Writer) error
	wait         func(context.Context) error
}

func defaultPendingServiceHooks() pendingServiceHooks {
	return pendingServiceHooks{identity: serviceIdentity, load: enrollmentclient.LoadBootstrap, inspect: enrollmentclient.InspectService, resume: enrollmentclient.ResumeService, markReady: enrollmentclient.MarkServiceReady, stopDeadline: enrollmentclient.StopServiceAtDeadline, sender: func(ctx context.Context, path string, interval time.Duration, out io.Writer) error {
		material, err := lanclient.Load(path)
		if err != nil {
			return enrollmentclient.ErrState
		}
		encoder := json.NewEncoder(out)
		_, err = lanclient.RunForeground(ctx, material, interval, func(event agentloop.Event) error {
			return encoder.Encode(struct {
				SchemaVersion string          `json:"schemaVersion"`
				Event         agentloop.Event `json:"event"`
			}{"tracebolt.agent-loop.v1", event})
		})
		return err
	}, wait: func(ctx context.Context) error {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}}
}

// No collector, spool or sender exists until both complete activation/handoff
// and the durable local ReadyObserved transition have succeeded. Hooks permit
// ordinary synthetic fixtures; production hooks keep all existing guards.
func runPendingService(ctx context.Context, o pendingServiceOptions, out, errOut io.Writer, h pendingServiceHooks) int {
	if ctx == nil || !h.identity(o.Identity) || !filepath.IsAbs(o.StateDirectory) || filepath.Clean(o.StateDirectory) != o.StateDirectory || o.ConfigPath != filepath.Join(o.StateDirectory, "agent.json") || o.Interval < 15*time.Second || o.Interval > time.Hour {
		fmt.Fprintln(errOut, "Pending-service identity or fixed-state inputs rejected before private-state access.")
		return 2
	}
	b, err := h.load(o.BootstrapPath)
	if err != nil || (b.Profile == "http-test") != o.InsecureHTTPTest {
		fmt.Fprintln(errOut, "Pending-service bootstrap/profile rejected.")
		return 2
	}
	if o.InsecureHTTPTest {
		fmt.Fprintln(errOut, "WARNING: UNENCRYPTED HTTP TEST. Manager responses are not authenticated; invitations and reports are visible.")
	}
	notify := func(p enrollmentclient.Progress) error {
		_, err := fmt.Fprintln(out, "Tracebolt enrollment phase: "+p.Phase)
		return err
	}
	for {
		if ctx.Err() != nil {
			return 0
		}
		state, err := h.inspect(b, o.StateDirectory, o.InsecureHTTPTest)
		if err != nil {
			if errors.Is(err, enrollmentclient.ErrServiceDeadline) {
				_ = h.stopDeadline(b, o.StateDirectory, o.InsecureHTTPTest)
			}
			fmt.Fprintln(errOut, "Pending-service retained state is invalid, stopped or past its local deadline. Preserve it for manual inspection.")
			return 2
		}
		if state.Ready {
			ready, err := h.markReady(b, o.StateDirectory, o.InsecureHTTPTest)
			if err != nil || !ready.Ready || ready.ConfigPath != o.ConfigPath {
				fmt.Fprintln(errOut, "Service handoff validation failed; state preserved.")
				return 2
			}
			err = h.sender(ctx, ready.ConfigPath, o.Interval, out)
			if err == nil || errors.Is(err, context.Canceled) {
				return 0
			}
			if errors.Is(err, enrollmentclient.ErrState) || errors.Is(err, agentloop.ErrState) || errors.Is(err, agentloop.ErrConfiguration) || errors.Is(err, agentloop.ErrRevoked) {
				return 2
			}
			fmt.Fprintln(errOut, "Tracebolt reporting stopped; inspect safe status and retained configuration.")
			return 1
		}
		fmt.Fprintln(out, "Tracebolt saved enrollment is pending; no inventory or logs are being collected.")
		_, err = h.resume(ctx, b, o.StateDirectory, o.InsecureHTTPTest, notify)
		if ctx.Err() != nil {
			return 0
		}
		if err == nil {
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, enrollmentclient.ErrTransport) {
			if h.wait(ctx) != nil {
				return 0
			}
			continue
		}
		fmt.Fprintln(errOut, "Pending enrollment stopped; approval, activation or reporting is not established. Retain the saved identity for manual inspection.")
		return 2
	}
}
