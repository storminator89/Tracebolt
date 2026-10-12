package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
)

type updateProvisionInput struct {
	coordinated *windowsupdatesetup.CoordinatedMaterial
	offer       job.SetupOffer
	artifact    windowspackage.Manifest
	payload     []byte
	schedule    bool
	apply       bool
	approval    windowsupdatesetup.Approval
}
type updateProvisionResult struct {
	plan         windowsupdatesetup.Plan
	registration job.SetupRegistration
}

func runUpdateProvision(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, updateProvisionInput) (updateProvisionResult, error)) int {
	f := flag.NewFlagSet("selected-updates-provision", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	offerPath := f.String("manager-offer", "", "")
	imagePath := f.String("executor-file", "", "")
	manifestPath := f.String("artifact-manifest", "", "")
	apply := f.Bool("apply", false, "")
	digest := f.String("approve", "", "")
	install := f.Bool("acknowledge-selected-updates", false, "")
	relay := f.Bool("acknowledge-observer-relay", false, "")
	query := f.Bool("acknowledge-observer-process-query", false, "")
	schedule := f.Bool("allow-scheduled-updates", false, "")
	scheduleAck := f.Bool("acknowledge-scheduled-updates", false, "")
	if f.Parse(args) != nil || f.NArg() != 0 || *offerPath == "" || *imagePath == "" || *manifestPath == "" || ctx == nil || perform == nil || *apply != (*digest != "") || *install != *apply || *relay != *apply || *query != *apply || *scheduleAck != (*apply && *schedule) {
		fmt.Fprintln(stderr, "Use --selected-updates-provision --manager-offer <public offer> --executor-file <matching executor.exe> --artifact-manifest <public manifest>. Review is read-only. Apply additionally requires --apply --approve sha256:<review digest> --acknowledge-selected-updates --acknowledge-observer-relay --acknowledge-observer-process-query. For fresh scheduling only, add --allow-scheduled-updates during both review and apply, and separately --acknowledge-scheduled-updates during apply. TLS only; no automatic launch.")
		return 2
	}
	raw, e := readUpdateSetupInput(*offerPath, 16384)
	if e != nil {
		return 1
	}
	offer, e := job.DecodeSetupOffer(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return 1
	}
	raw, e = readUpdateSetupInput(*manifestPath, 4096)
	if e != nil {
		return 1
	}
	manifest, e := windowspackage.ParseManifest(raw)
	if e != nil {
		return 1
	}
	payload, e := readUpdateSetupInput(*imagePath, windowspackage.MaxPayloadBytes)
	if e != nil || manifest.Validate(payload) != nil {
		return 1
	}
	if _, e = fmt.Fprintln(stderr, job.Disclosure+"\n"+lanclient.WindowsUpdateRelayDisclosure+"\n"+windowsupdatesetup.ProcessQueryDisclosure); e != nil {
		return 1
	}
	if *schedule {
		if _, e = fmt.Fprintln(stderr, windowsupdatesetup.ScheduleDisclosure); e != nil {
			return 1
		}
	}
	result, e := perform(ctx, updateProvisionInput{offer: offer, artifact: manifest, payload: payload, apply: *apply, schedule: *schedule, approval: windowsupdatesetup.Approval{Digest: *digest, Install: *install, Relay: *relay, ProcessQuery: *query, Schedule: *scheduleAck}})
	if e != nil {
		fmt.Fprintln(stderr, "Selected update setup blocked: exact activated TLS identity, stopped owned observer, fresh state and explicit original approval are required. Preserve partial state; do not retry, adopt or reset it.")
		return 1
	}
	if *apply {
		if result.registration.Validate() != nil {
			return 1
		}
		if e = json.NewEncoder(out).Encode(result.registration); e != nil {
			return 1
		}
		fmt.Fprintln(stderr, "Local setup complete; stdout is the public manager registration. Observer remains stopped. Executor was not launched. Complete separately approved manager registration before explicit foreground launch.")
	} else {
		if e = json.NewEncoder(out).Encode(result.plan); e != nil {
			return 1
		}
		fmt.Fprintln(stderr, "Review digest:", result.plan.Digest())
	}
	return 0
}
func readUpdateSetupInput(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	ce := f.Close()
	if e != nil || ce != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, windowsupdatesetup.ErrSetup
	}
	return raw, nil
}
func runUpdateRemove(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, bool, string) (windowsupdatesetup.RemovalPlan, error)) int {
	f := flag.NewFlagSet("selected-updates-remove", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	apply := f.Bool("apply", false, "")
	digest := f.String("approve", "", "")
	ack := f.Bool("acknowledge-remove-selected-updates", false, "")
	if f.Parse(args) != nil || f.NArg() != 0 || ctx == nil || perform == nil || *apply != (*digest != "") || *ack != *apply {
		fmt.Fprintln(stderr, "Use --selected-updates-remove for read-only review. Apply requires --apply --approve sha256:<review digest> --acknowledge-remove-selected-updates. Stop the observer and foreground executor first. Removal retires the relay/key and removes only the owned image; used records and tombstones remain.")
		return 2
	}
	p, e := perform(ctx, *apply, *digest)
	if e != nil {
		fmt.Fprintln(stderr, "Selected update removal blocked: stopped owned observer, exclusive executor state, complete ownership and resolved attempts are required. Preserve partial state; no unknown file was adopted.")
		return 1
	}
	if e = json.NewEncoder(out).Encode(p); e != nil {
		return 1
	}
	fmt.Fprintln(stderr, "Removal review digest:", p.Digest())
	if *apply {
		fmt.Fprintln(stderr, "Selected update authority retired. Owned executor image removed; nonsecret original consent, used records and removal tombstone retained. This does not cancel manager permits or undo an update.")
	}
	return 0
}
func runUpdateExport(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context) (job.SetupRegistration, error)) int {
	if len(args) != 0 || ctx == nil || perform == nil {
		return 2
	}
	r, e := perform(ctx)
	if e != nil || r.Validate() != nil {
		fmt.Fprintln(stderr, "Public registration unavailable: complete unchanged owned setup is required; no state was created or reset.")
		return 1
	}
	if json.NewEncoder(out).Encode(r) != nil {
		return 1
	}
	return 0
}
