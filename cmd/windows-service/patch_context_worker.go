package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowspatchworker"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdates"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runPatchContextWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	return servePatchContextWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsPatchContextWorkerRequest, windowsupdates.CollectPatchContext)
}

func servePatchContextWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowspatchcontext.Request) (windowspatchcontext.Request, error), collect func(context.Context, windowspatchcontext.Request) (windowspatchcontext.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowspatchworker.Serve(ctx, in, out, func(ctx context.Context, request windowspatchcontext.Request) (windowspatchcontext.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowspatchcontext.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowspatchcontext.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
