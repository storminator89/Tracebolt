package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/lanclient"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiservice"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowsupdatejob"
)

type managedMSIPlan struct {
	MutationPlanDigest string                                   `json:"mutationPlanDigest,omitempty"`
	Version            string                                   `json:"version"`
	Offer              managed.SetupOffer                       `json:"offer"`
	Artifact           windowspackage.Manifest                  `json:"artifact"`
	Identity           lanclient.WindowsManagedMSISetupIdentity `json:"identity"`
	Observer           windowsservice.Receipt                   `json:"observer"`
	DeliveryDisclosure string                                   `json:"deliveryDisclosure"`
	InstallDisclosure  string                                   `json:"installDisclosure"`
	ServiceDisclosure  string                                   `json:"serviceDisclosure"`
	RelayDisclosure    string                                   `json:"relayDisclosure"`
}

func (p managedMSIPlan) Digest() string {
	b, _ := json.Marshal(p)
	if p.Offer.Version == managed.ReusableOfferVersion {
		return managed.Digest(append([]byte("Tracebolt reusable MSI endpoint setup v3\x00"), b...))
	}
	return managed.Digest(append([]byte("Tracebolt managed MSI endpoint setup v1\x00"), b...))
}

type managedMSIInput struct {
	coordinated *coordinatedMSIMaterial
	offer       managed.SetupOffer
	artifact    windowspackage.Manifest
	payload     []byte
	apply       bool
	digest      string
}
type managedMSIResult struct {
	plan         managedMSIPlan
	registration managed.SetupRegistration
	configDigest string
}

func runManagedMSIProvision(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, managedMSIInput) (managedMSIResult, error)) int {
	f := flag.NewFlagSet("managed-msi-provision", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	offerPath := f.String("manager-offer", "", "")
	imagePath := f.String("service-file", "", "")
	manifestPath := f.String("artifact-manifest", "", "")
	apply := f.Bool("apply", false, "")
	digest := f.String("approve", "", "")
	delivery := f.Bool("acknowledge-managed-delivery", false, "")
	install := f.Bool("acknowledge-one-managed-install", false, "")
	risk := f.Bool("acknowledge-localsystem-risk", false, "")
	relay := f.Bool("acknowledge-observer-relay", false, "")
	query := f.Bool("acknowledge-observer-process-query", false, "")
	if f.Parse(args) != nil || f.NArg() != 0 || ctx == nil || perform == nil || *offerPath == "" || *imagePath == "" || *manifestPath == "" || *apply != (*digest != "") || *delivery != *apply || *install != *apply || *risk != *apply || *relay != *apply || *query != *apply {
		fmt.Fprintln(stderr, "Use --managed-msi-provision --manager-offer <public offer> --service-file <matching service.exe> --artifact-manifest <public manifest>. Review is read-only. Apply requires --apply --approve sha256:<exact plan> --acknowledge-managed-delivery --acknowledge-one-managed-install --acknowledge-localsystem-risk --acknowledge-observer-relay --acknowledge-observer-process-query. No MSI is selected or installed by setup.")
		return 2
	}
	raw, e := readSoftwareSetupInput(*offerPath, 16384)
	if e != nil {
		return 1
	}
	offer, e := managed.DecodeSetupOffer(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return 1
	}
	raw, e = readSoftwareSetupInput(*manifestPath, 4096)
	if e != nil {
		return 1
	}
	artifact, e := windowspackage.ParseManifest(raw)
	if e != nil || artifact.Architecture != "amd64" {
		return 1
	}
	payload, e := readSoftwareSetupInput(*imagePath, windowspackage.MaxPayloadBytes)
	if e != nil || artifact.Validate(payload) != nil {
		return 1
	}
	fmt.Fprintln(stderr, managed.DeliveryDisclosure+"\n"+managed.InstallDisclosure+"\n"+managed.ServiceDisclosure+"\n"+lanclient.WindowsManagedMSIRelayDisclosure)
	r, e := perform(ctx, managedMSIInput{offer: offer, artifact: artifact, payload: payload, apply: *apply, digest: *digest})
	if e != nil {
		fmt.Fprintln(stderr, "Managed MSI setup blocked. Preserve partial state; do not retry, adopt or reset it. No completion is claimed.")
		return 1
	}
	if *apply {
		if r.registration.Validate() != nil || json.NewEncoder(out).Encode(r.registration) != nil {
			return 1
		}
		fmt.Fprintln(stderr, "Public configuration digest:", r.configDigest)
		fmt.Fprintln(stderr, "Dedicated service staged disabled; observer remains stopped. Complete manager finalization, explicitly start the observer, then separately activate the deployment service.")
	} else {
		if json.NewEncoder(out).Encode(r.plan) != nil {
			return 1
		}
		fmt.Fprintln(stderr, "Review digest:", r.plan.Digest())
	}
	return 0
}
func runManagedMSIActivate(ctx context.Context, args []string, out, stderr io.Writer) int {
	f := flag.NewFlagSet("managed-msi-activate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	apply := f.Bool("apply", false, "")
	ack := f.Bool("acknowledge-start-localsystem-service", false, "")
	digest := f.String("approve-config", "", "")
	backgroundRegistration := f.String("background-registration", "", "")
	managerActivation := f.String("manager-activation", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || !*apply || !*ack || !managed.ValidDigest(*digest) || (*backgroundRegistration == "") != (*managerActivation == "") {
		fmt.Fprintln(stderr, "Activation requires --apply --acknowledge-start-localsystem-service --approve-config sha256:<reviewed public configuration> after manager finalization and observer startup. Fresh background pairing also requires --background-registration and --manager-activation public files.")
		return 2
	}
	var proof *windowsmanagedmsiservice.BackgroundRegistrationProof
	if *backgroundRegistration != "" {
		raw, e := readSoftwareSetupInput(*backgroundRegistration, 16385)
		if e != nil {
			return 1
		}
		registration, e := job.DecodeSetupRegistration(bytes.TrimSuffix(raw, []byte("\n")))
		if e != nil {
			return 1
		}
		raw, e = readSoftwareSetupInput(*managerActivation, 4096)
		if e != nil {
			return 1
		}
		var manager job.BackgroundActivation
		if managed.Canonical(bytes.TrimSuffix(raw, []byte("\n")), &manager, 4096) != nil || manager.Verify(registration) != nil {
			return 1
		}
		proof = &windowsmanagedmsiservice.BackgroundRegistrationProof{Registration: registration, Manager: manager}
	}
	if e := nativeManagedMSIActivate(ctx, *digest, proof); e != nil {
		fmt.Fprintln(stderr, "Deployment service activation is unconfirmed. Preserve its activation intent; do not repeat or reset it.")
		return 1
	}
	fmt.Fprintln(out, "Deployment service activation submitted; verify SCM and fresh signed delivery state. No package installation is authorized by service uptime.")
	return 0
}

func runManagedMSIExport(ctx context.Context, args []string, out, stderr io.Writer) int {
	if len(args) != 0 {
		return 2
	}
	result, e := nativeManagedMSIExport(ctx)
	if e != nil || result.registration.Validate() != nil || !managed.ValidDigest(result.configDigest) {
		fmt.Fprintln(stderr, "Completed managed MSI registration unavailable; nothing was recreated or reset.")
		return 1
	}
	if json.NewEncoder(out).Encode(result.registration) != nil {
		return 1
	}
	fmt.Fprintln(stderr, "Public configuration digest:", result.configDigest)
	return 0
}
