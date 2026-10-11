package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsupdateworker"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runUpdatesWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	return serveUpdatesWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsUpdatesWorkerRequest, windowsupdates.Collect)
}

func serveUpdatesWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowsupdates.Request) (windowsupdates.Request, error), collect func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowsupdateworker.Serve(ctx, in, out, func(ctx context.Context, request windowsupdates.Request) (windowsupdates.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowsupdates.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowsupdates.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
