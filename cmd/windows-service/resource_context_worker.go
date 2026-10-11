package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowsresourceworker"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runResourceContextWorker(ctx context.Context, in io.Reader, out io.Writer, source string) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	collect := windowsresourcecontext.CollectNativeProcessors
	switch source {
	case "processors":
	case "installed-memory":
		collect = windowsresourcecontext.CollectNativeInstalledMemory
	case "memory":
		collect = windowsresourcecontext.CollectNativeMemory
	case "pagefiles":
		collect = windowsresourcecontext.CollectNativePagefiles
	default:
		return lanclient.ErrConfiguration
	}

	return serveResourceContextWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsResourceContextWorkerRequest, collect)
}

func serveResourceContextWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowsresourcecontext.Request) (windowsresourcecontext.Request, error), collect func(context.Context, windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowsresourceworker.Serve(ctx, in, out, func(ctx context.Context, request windowsresourcecontext.Request) (windowsresourcecontext.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowsresourcecontext.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowsresourcecontext.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
