package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"localrmm/internal/windowsservice"
)

type readAdminContinuationRequest struct {
	apply    bool
	approval string
}

func runReadAdminContinuation(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, readAdminContinuationRequest) (readAdminContinuationPlan, error)) int {
	f := flag.NewFlagSet("read-admin-recover", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	apply := f.Bool("apply", false, "")
	approve := f.String("approve", "", "")
	ack := f.Bool("acknowledge-read-admin-recovery", false, "")
	if f.Parse(args) != nil || f.NArg() != 0 || ctx == nil || ctx.Err() != nil || perform == nil || *apply != *ack || *apply != (*approve != "") || *apply && (!strings.HasPrefix(*approve, "sha256:") || !validReadSetupBinding(strings.TrimPrefix(*approve, "sha256:"))) {
		fmt.Fprintln(stderr, "Use --read-admin-recover for a read-only plan. Apply requires --apply --approve sha256:<exact plan digest> --acknowledge-read-admin-recovery. TLS-only source candidate; native acceptance is separate.")
		return 2
	}
	if writeReadSetupDisclosureWithIntro(out, freshReadAdminSetupConsent(false), "Same-identity recovery uses the retained LocalService service and protected endpoint identity. Only the originally acknowledged read scopes below may be completed; original manager fingerprint approval remains mandatory.") != nil {
		return 1
	}
	text := "Recovery continues one already-claimed original identity within its original pending deadline. The one attempt is durably fenced before network access; uncertainty cannot be retried. Only the original 21 read scopes are completed before startup. No invitation, new identity, installation, reset or security exception is supported.\n"
	if n, e := io.WriteString(out, text); e != nil || n != len(text) {
		return 1
	}
	result, err := perform(ctx, readAdminContinuationRequest{*apply, *approve})
	if err != nil {
		reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonOperationFailed, err))
		return 1
	}
	if writeLifecycleResult(out, result) != nil {
		return 1
	}
	return 0
}
