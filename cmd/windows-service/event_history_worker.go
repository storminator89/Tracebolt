package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryworker"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

func runEventHistoryWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	stop := startEventContentWorkerWatchdog()
	defer stop()
	return serveEventHistoryWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsEventHistoryWorkerRequest, lanclient.ConsumeWindowsEventHistoryWorkerRequest, func(ctx context.Context, r windowshistoryworker.Request) (windowseventhistory.Report, error) {
		return windowseventhistory.Read(ctx, r.Description.Query)
	})
}

// ValidateObservationWorker binds the actual process creator PID and creation
// times to the exact running own-process SCM service, its restricted LocalService
// token/service SID, fixed protected executable/hash and configuration. Repeating
// it around consumption and capture rejects parent substitution and PID reuse.
func serveEventHistoryWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowshistoryworker.Request) (windowshistoryworker.Request, error), consume func(context.Context, string, windowshistoryworker.Request) error, read func(context.Context, windowshistoryworker.Request) (windowseventhistory.Report, error)) error {
	if identify == nil || authorize == nil || consume == nil || read == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	resolve := func(ctx context.Context, r windowshistoryworker.Request) (windowshistoryworker.Request, error) {
		identity, e := identify(ctx)
		if e != nil {
			return windowshistoryworker.Request{}, e
		}
		if checks > 0 && identity != first {
			return windowshistoryworker.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), r)
	}
	return windowshistoryworker.Serve(ctx, in, out, resolve, func(ctx context.Context, r windowshistoryworker.Request) error {
		if _, e := resolve(ctx, r); e != nil {
			return e
		}
		return consume(ctx, filepath.Join(first.Layout.EnrollmentRoot, "agent.json"), r)
	}, read)
}
