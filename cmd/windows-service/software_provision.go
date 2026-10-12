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
	job "localrmm/internal/windowssoftwarejob"
	"localrmm/internal/windowssoftwaresetup"
)

type softwareProvisionInput struct {
	offer          job.SetupOffer
	artifact       windowspackage.Manifest
	payload        []byte
	selection      job.Selection
	acceptance     string
	packagePayload []byte
	apply          bool
	approval       windowssoftwaresetup.Approval
}
type softwareProvisionResult struct {
	plan         windowssoftwaresetup.Plan
	registration job.SetupRegistration
}

func runSoftwareProvision(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, softwareProvisionInput) (softwareProvisionResult, error)) int {
	f := flag.NewFlagSet("prepared-msi-provision", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	offerPath := f.String("manager-offer", "", "")
	imagePath := f.String("executor-file", "", "")
	manifestPath := f.String("artifact-manifest", "", "")
	apply := f.Bool("apply", false, "")
	digest := f.String("approve", "", "")
	install := f.Bool("acknowledge-prepared-msi", false, "")
	relay := f.Bool("acknowledge-observer-relay", false, "")
	query := f.Bool("acknowledge-observer-process-query", false, "")
	packagePath := f.String("package-file", "", "")
	reviewPath := f.String("package-review", "", "")
	reviewAck := f.Bool("acknowledge-package-risk-and-terms", false, "")
	nativeAck := f.Bool("acknowledge-package-native-acceptance", false, "")
	if f.Parse(args) != nil || f.NArg() != 0 || *offerPath == "" || *imagePath == "" || *manifestPath == "" || ctx == nil || perform == nil || *apply != (*digest != "") || *install != *apply || *relay != *apply || *query != *apply || *reviewAck != *apply || *nativeAck != *apply || *packagePath == "" || *reviewPath == "" {
		fmt.Fprintln(stderr, "Use --prepared-msi-provision --manager-offer <public offer> --executor-file <matching executor.exe> --artifact-manifest <public manifest>. Review is read-only. Apply additionally requires --apply --approve sha256:<review digest> --acknowledge-prepared-msi --acknowledge-observer-relay --acknowledge-observer-process-query. Both phases require --package-file <reviewed.msi> --package-review <canonical review.json>. Apply requires --acknowledge-package-risk-and-terms --acknowledge-package-native-acceptance. Package metadata is administrator-reviewed; native verification happens only during protected staging. TLS only; no automatic launch.")
		return 2
	}
	raw, e := readSoftwareSetupInput(*offerPath, 16384)
	if e != nil {
		return 1
	}
	offer, e := job.DecodeSetupOffer(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return 1
	}
	raw, e = readSoftwareSetupInput(*manifestPath, 4096)
	if e != nil {
		return 1
	}
	manifest, e := windowspackage.ParseManifest(raw)
	if e != nil {
		return 1
	}
	payload, e := readSoftwareSetupInput(*imagePath, windowspackage.MaxPayloadBytes)
	if e != nil || manifest.Validate(payload) != nil {
		return 1
	}
	if _, e = fmt.Fprintln(stderr, job.Disclosure+"\n"+lanclient.WindowsSoftwareRelayDisclosure+"\n"+windowssoftwaresetup.ProcessQueryDisclosure); e != nil {
		return 1
	}

	reviewRaw, e := readSoftwareSetupInput(*reviewPath, 4096)
	var review struct {
		Package                job.Selection `json:"package"`
		NativeAcceptanceDigest string        `json:"nativeAcceptanceDigest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(reviewRaw))
	decoder.DisallowUnknownFields()
	if e != nil || decoder.Decode(&review) != nil || !job.ValidSelection(review.Package) {
		return 1
	}
	canonical, _ := json.Marshal(review)
	if !bytes.Equal(bytes.TrimSuffix(reviewRaw, []byte("\n")), canonical) {
		return 1
	}
	packagePayload, e := readSoftwareSetupInput(*packagePath, windowspackage.MaxPayloadBytes)
	if e != nil || windowspackage.ValidatePreparedMSIBytes(packagePayload, review.Package) != nil {
		return 1
	}
	result, e := perform(ctx, softwareProvisionInput{offer: offer, artifact: manifest, payload: payload, apply: *apply, selection: review.Package, acceptance: review.NativeAcceptanceDigest, packagePayload: packagePayload, approval: windowssoftwaresetup.Approval{Digest: *digest, Install: *install, Relay: *relay, ProcessQuery: *query, PackageReview: *reviewAck, NativeAcceptance: *nativeAck}})
	if e != nil {
		fmt.Fprintln(stderr, "Prepared MSI setup blocked: exact activated TLS identity, stopped owned observer, fresh state and explicit original approval are required. Preserve partial state; do not retry, adopt or reset it.")
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
func readSoftwareSetupInput(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	ce := f.Close()
	if e != nil || ce != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, windowssoftwaresetup.ErrSetup
	}
	return raw, nil
}

func runSoftwareExport(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context) (job.SetupRegistration, error)) int {
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
