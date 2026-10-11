package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowssessionworker"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runSessionContextWorker(ctx context.Context, in io.Reader, out io.Writer, join bool) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	collect := windowssessions.CollectNativeSessions
	if join {
		collect = windowssessions.CollectNativeJoin
	}
	return serveSessionContextWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsSessionContextWorkerRequest, collect)
}

func serveSessionContextWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowssessions.Request) (windowssessions.Request, error), collect func(context.Context, windowssessions.Request) (windowssessions.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowssessionworker.Serve(ctx, in, out, func(ctx context.Context, request windowssessions.Request) (windowssessions.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowssessions.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowssessions.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
