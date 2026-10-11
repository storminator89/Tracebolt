package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecurityworker"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runSecurityPostureWorker(ctx context.Context, in io.Reader, out io.Writer, firewall bool) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	collect := windowssecurity.CollectNativeDefender
	if firewall {
		collect = windowssecurity.CollectNativeFirewall
	}
	return serveSecurityPostureWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsSecurityPostureWorkerRequest, collect)
}

func serveSecurityPostureWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowssecurity.Request) (windowssecurity.Request, error), collect func(context.Context, windowssecurity.Request) (windowssecurity.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowssecurityworker.Serve(ctx, in, out, func(ctx context.Context, request windowssecurity.Request) (windowssecurity.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowssecurity.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowssecurity.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
