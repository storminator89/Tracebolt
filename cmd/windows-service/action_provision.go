package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"localrmm/internal/windowsaction"
	"localrmm/internal/windowspackage"
)

type actionProvisionInput struct {
	policy          windowsaction.Policy
	artifact        windowspackage.Manifest
	payload         []byte
	apply, insecure bool
	approved        string
}

func runActionProvision(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, actionProvisionInput) (windowsaction.ProvisionPlan, error)) int {
	flags := flag.NewFlagSet("service-actions-provision", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy-file", "", "")
	brokerPath := flags.String("broker-file", "", "")
	manifestPath := flags.String("artifact-manifest", "", "")
	apply := flags.Bool("apply", false, "")
	approve := flags.String("approve", "", "")
	consent := flags.Bool("acknowledge-service-control", false, "")
	http := flags.Bool("insecure-http-test", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *policyPath == "" || *brokerPath == "" || *manifestPath == "" || *apply != (*approve != "") || *apply != *consent || ctx == nil || perform == nil {
		fmt.Fprintln(stderr, "Use --service-actions-provision --policy-file <reviewed policy> --broker-file <matching broker.exe> --artifact-manifest <public manifest>. Read-only plan is default. Apply additionally requires --apply --approve sha256:<exact plan digest> --acknowledge-service-control.")
		return 2
	}
	read := func(path string, limit int64) ([]byte, error) {
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		raw, e := io.ReadAll(io.LimitReader(f, limit+1))
		ce := f.Close()
		if e != nil || ce != nil || len(raw) == 0 || int64(len(raw)) > limit {
			return nil, windowsaction.ErrInvalid
		}
		return raw, nil
	}
	raw, e := read(*policyPath, windowsaction.MaxMessageBytes)
	if e != nil {
		return 1
	}
	var p windowsaction.Policy
	if windowsaction.DecodeCanonical(raw, &p, windowsaction.MaxMessageBytes) != nil || windowsaction.ValidatePolicy(p) != nil || !p.Enabled {
		return 1
	}
	raw, e = read(*manifestPath, 4096)
	if e != nil {
		return 1
	}
	manifest, e := windowspackage.ParseManifest(raw)
	if e != nil {
		return 1
	}
	payload, e := read(*brokerPath, windowspackage.MaxPayloadBytes)
	if e != nil || manifest.Validate(payload) != nil {
		return 1
	}
	if _, e = fmt.Fprintln(out, windowsaction.ProvisionConsent); e != nil {
		return 1
	}
	if *http {
		if _, e = fmt.Fprintln(out, "HTTP test transport exposes action/operator data; a stolen operator session can authorize this selected target. Isolated disposable LAN only."); e != nil {
			return 1
		}
	}
	plan, e := perform(ctx, actionProvisionInput{p, manifest, payload, *apply, *http, *approve})
	if e != nil {
		fmt.Fprintln(stderr, windowsaction.ProvisionDiagnostic(e))
		fmt.Fprintln(stderr, "Preserve every partial object and receipt; do not retry as fresh. Target must already be a reviewed LocalService own-process application with a protected quoted image, no arguments/dependencies/recovery/triggers, and only SeChangeNotifyPrivilege. Existing targets are never reconfigured to fit.")
		return 1
	}
	if e = json.NewEncoder(out).Encode(plan); e != nil {
		return 1
	}
	if _, e = fmt.Fprintln(out, "Plan digest:", plan.Digest()); e != nil {
		return 1
	}
	if *apply {
		fmt.Fprintln(out, "Provisioned and verified; broker remains disabled, observer remains stopped. Enabling/start and every target action require separate approval.")
	}
	return 0
}
