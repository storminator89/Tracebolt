package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowshardwareworker"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runHardwareContextWorker(ctx context.Context, in io.Reader, out io.Writer, source string) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	collect := windowshardware.CollectNativeSystem
	switch source {
	case "system":
	case "firmware":
		collect = windowshardware.CollectNativeFirmware
	case "chassis":
		collect = windowshardware.CollectNativeChassis
	case "power":
		collect = windowshardware.CollectNativePower
	default:
		return lanclient.ErrConfiguration
	}

	return serveHardwareContextWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsHardwareContextWorkerRequest, collect)
}

func serveHardwareContextWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowshardware.Request) (windowshardware.Request, error), collect func(context.Context, windowshardware.Request) (windowshardware.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowshardwareworker.Serve(ctx, in, out, func(ctx context.Context, request windowshardware.Request) (windowshardware.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowshardware.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowshardware.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
