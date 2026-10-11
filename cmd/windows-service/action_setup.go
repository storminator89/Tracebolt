package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/windowsaction"
	"os"
)

type actionSetupInput struct {
	policy          windowsaction.Policy
	raw             []byte
	apply, insecure bool
}

func runActionSetup(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, actionSetupInput) error) int {
	flags := flag.NewFlagSet("service-actions-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("policy-file", "", "")
	apply := flags.Bool("apply", false, "")
	approve := flags.String("approve", "", "")
	http := flags.Bool("insecure-http-test", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || *apply != (*approve != "") || ctx == nil || perform == nil {
		fmt.Fprintln(stderr, "Use --service-actions-setup --policy-file <reviewed local policy>. Apply requires --apply --approve sha256:<exact policy digest>.")
		return 2
	}
	f, e := os.Open(*path)
	if e != nil {
		return 1
	}
	raw, e := io.ReadAll(io.LimitReader(f, windowsaction.MaxMessageBytes+1))
	ce := f.Close()
	var policy windowsaction.Policy
	if e != nil || ce != nil || windowsaction.DecodeCanonical(raw, &policy, windowsaction.MaxMessageBytes) != nil || windowsaction.ValidatePolicy(policy) != nil || !policy.Enabled {
		return 1
	}
	digest := windowsaction.Digest(raw)
	if *apply && *approve != digest {
		return 2
	}
	if _, e = fmt.Fprintln(out, "Selected Windows service control: start, stop and restart of the one reviewed target. This creates independent local authority; existing observation scopes do not grant it. No target action is performed. Partial setup is retained and cannot be retried as fresh."); e != nil {
		return 1
	}
	if *http {
		if _, e = fmt.Fprintln(out, "HTTP test transport exposes action and operator data; a stolen operator session can authorize this target. Use only an isolated disposable LAN."); e != nil {
			return 1
		}
	}
	if e = perform(ctx, actionSetupInput{policy, raw, *apply, *http}); e != nil {
		fmt.Fprintln(stderr, "Setup unavailable or incomplete. Preserve all existing authority and state; no reset was performed.")
		return 1
	}
	fmt.Fprintln(out, digest)
	return 0
}
