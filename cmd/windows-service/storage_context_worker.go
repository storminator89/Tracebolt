package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageworker"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runStorageContextWorker(ctx context.Context, in io.Reader, out io.Writer, source string) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	collect := windowsstorage.CollectNativeDrives
	switch source {
	case "drives":
	case "disks":
		collect = windowsstorage.CollectNativeDisks
	default:
		return lanclient.ErrConfiguration
	}

	return serveStorageContextWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsStorageContextWorkerRequest, collect)
}

func serveStorageContextWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowsstorage.Request) (windowsstorage.Request, error), collect func(context.Context, windowsstorage.Request) (windowsstorage.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowsstorageworker.Serve(ctx, in, out, func(ctx context.Context, request windowsstorage.Request) (windowsstorage.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowsstorage.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowsstorage.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
