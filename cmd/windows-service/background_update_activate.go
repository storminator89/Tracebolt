package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/actionpermit"
	job "localrmm/internal/windowsupdatejob"
)

func runBackgroundUpdateActivate(ctx context.Context, args []string, out, stderr io.Writer) int {
	f := flag.NewFlagSet("background-updates-activate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	apply := f.Bool("apply", false, "")
	ack := f.Bool("acknowledge-start-localsystem-service", false, "")
	digest := f.String("approve-config", "", "")
	receipt := f.String("manager-activation", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || !*apply || !*ack || !actionpermit.ValidDigest(*digest) || *receipt == "" {
		fmt.Fprintln(stderr, "Activation requires --apply --acknowledge-start-localsystem-service --approve-config <exact digest> --manager-activation <manager-signed registration receipt> after both registrations and observer startup.")
		return 2
	}
	raw, e := readUpdateSetupInput(*receipt, 4096)
	if e != nil {
		return 1
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	var a job.BackgroundActivation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil {
		return 1
	}
	canonical, _ := json.Marshal(a)
	if !bytes.Equal(raw, canonical) {
		return 1
	}
	if nativeBackgroundUpdateActivate(ctx, *digest, a) != nil {
		fmt.Fprintln(stderr, "Background update activation is unconfirmed. Preserve the durable intent; do not repeat or reset it.")
		return 1
	}
	fmt.Fprintln(out, "Background update service activation submitted. Verify fresh signed executor status; each cached update still requires its own approval.")
	return 0
}
