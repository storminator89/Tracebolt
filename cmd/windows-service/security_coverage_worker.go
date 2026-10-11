package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssecuritycoverageworker"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// The child retains the service token, never elevates or reads the installer-only
// receipt. Both resolver calls derive fixed paths from the verified SCM binding.
func runSecurityCoverageWorker(ctx context.Context, in io.Reader, out io.Writer, source string) error {
	stopWatchdog := startUpdatesWorkerWatchdog()
	defer stopWatchdog()
	collect := windowssecuritycoverage.CollectNativeAntivirus
	switch source {
	case "antivirus":
	case "tpm":
		collect = windowssecuritycoverage.CollectNativeTPM
	default:
		return lanclient.ErrConfiguration
	}

	return serveSecurityCoverageWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsSecurityCoverageWorkerRequest, collect)
}

func serveSecurityCoverageWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowssecuritycoverage.Request) (windowssecuritycoverage.Request, error), collect func(context.Context, windowssecuritycoverage.Request) (windowssecuritycoverage.Snapshot, error)) error {
	if identify == nil || authorize == nil || collect == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	return windowssecuritycoverageworker.Serve(ctx, in, out, func(ctx context.Context, request windowssecuritycoverage.Request) (windowssecuritycoverage.Request, error) {
		identity, err := identify(ctx)
		if err != nil {
			return windowssecuritycoverage.Request{}, err
		}
		if checks > 0 && identity != first {
			return windowssecuritycoverage.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), request)
	}, collect)
}
