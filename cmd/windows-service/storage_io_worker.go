package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsstorageioworker"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runStorageIOWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	return serveStorageIOWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsStorageIOWorkerRequest, windowsstorageio.CollectNative)
}

func serveStorageIOWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowsstorageio.Request) (windowsstorageio.Request, error), collect func(context.Context, windowsstorageio.Request) (windowsstorageio.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowsstorageioworker.Serve(ctx, in, out, func(ctx context.Context, request windowsstorageio.Request) (windowsstorageio.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowsstorageio.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowsstorageio.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
