package main

import (
	"context"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventworker"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

func runEventContentWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	stop := startEventContentWorkerWatchdog()
	defer stop()
	return serveEventContentWorker(ctx, in, out, windowsservice.ValidateObservationWorker, lanclient.ValidateWindowsEventContentWorkerRequest, lanclient.ConsumeWindowsEventContentWorkerRequest, func(ctx context.Context, r windowseventworker.Request) (windowseventcontent.Report, error) {
		return windowseventcontent.Read(ctx, r.Description.Query)
	})
}

// ValidateObservationWorker binds the actual process creator PID and creation
// times to the exact running own-process SCM service, its restricted LocalService
// token/service SID, fixed protected executable/hash and configuration. Repeating
// it around consumption and capture rejects parent substitution and PID reuse.
func serveEventContentWorker(ctx context.Context, in io.Reader, out io.Writer, identify func(context.Context) (windowsservice.ObservationWorkerIdentity, error), authorize func(string, windowseventworker.Request) (windowseventworker.Request, error), consume func(context.Context, string, windowseventworker.Request) error, read func(context.Context, windowseventworker.Request) (windowseventcontent.Report, error)) error {
	if identify == nil || authorize == nil || consume == nil || read == nil {
		return lanclient.ErrConfiguration
	}
	var first windowsservice.ObservationWorkerIdentity
	checks := 0
	resolve := func(ctx context.Context, r windowseventworker.Request) (windowseventworker.Request, error) {
		identity, e := identify(ctx)
		if e != nil {
			return windowseventworker.Request{}, e
		}
		if checks > 0 && identity != first {
			return windowseventworker.Request{}, lanclient.ErrState
		}
		if checks == 0 {
			first = identity
		}
		checks++
		return authorize(filepath.Join(identity.Layout.EnrollmentRoot, "agent.json"), r)
	}
	return windowseventworker.Serve(ctx, in, out, resolve, func(ctx context.Context, r windowseventworker.Request) error {
		if _, e := resolve(ctx, r); e != nil {
			return e
		}
		return consume(ctx, filepath.Join(first.Layout.EnrollmentRoot, "agent.json"), r)
	}, read)
}
