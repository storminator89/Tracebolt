package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/lanclient"
	managed "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
)

const reusableMutationVersion = "tracebolt.windows-coordinated-mutation-setup.v2"
const coordinatedMutationVersion = "tracebolt.windows-coordinated-mutation-setup.v1"
const coordinatedMutationDisclosure = "Set up separate managed MSI delivery/install and selected cached Windows Update permissions on this exact endpoint. The deployment service runs as LocalSystem; package custom actions are not sandboxed and can affect services, applications and the network. Only package/native-reviewed synchronous MSI without detached deployment or rollback work is eligible. This paired profile supports manual update approval, not scheduled intents. Windows Updates still require an explicitly launched elevated foreground executor and process-query approval. One durable shared owner blocks the other domain; crashes, unknown completion and partial setup require intervention, never automatic unlock, retry, reset or reboot. Prepared MSI and service-control brokers remain incompatible."

type coordinatedMSIMaterial struct {
	Roster fence.Roster
	Key    ed25519.PrivateKey
	Grant  managed.Grant
}
type coordinatedMutationInput struct {
	MSI    managedMSIInput
	WUA    updateProvisionInput
	Apply  bool
	Digest string
}
type coordinatedMutationPlan struct {
	Version    string                  `json:"version"`
	MSI        managedMSIPlan          `json:"msi"`
	WUA        windowsupdatesetup.Plan `json:"wua"`
	Disclosure string                  `json:"disclosure"`
}
type coordinatedMutationResult struct {
	Plan            coordinatedMutationPlan   `json:"plan"`
	MSI             managed.SetupRegistration `json:"msi"`
	WUA             job.SetupRegistration     `json:"wua"`
	MSIConfigDigest string                    `json:"msiConfigDigest"`
	FenceDigest     string                    `json:"fenceDigest"`
}

func (p coordinatedMutationPlan) Digest() string {
	b, _ := json.Marshal(p)
	if p.Version == reusableMutationVersion {
		return managed.Digest(append([]byte("Tracebolt fresh reusable Windows mutation setup v2\x00"), b...))
	}
	return managed.Digest(append([]byte("Tracebolt fresh coordinated Windows mutation setup v1\x00"), b...))
}
func (p coordinatedMutationPlan) Validate() error {
	m, w := p.MSI, p.WUA
	reusable := p.Version == reusableMutationVersion
	if (p.Version != coordinatedMutationVersion && !reusable) || (m.Offer.Version == managed.ReusableOfferVersion) != reusable || !reusable && (p.Disclosure != coordinatedMutationDisclosure || m.Version != "tracebolt.windows-managed-msi-endpoint-plan.v1") || reusable && (p.Disclosure != coordinatedMutationDisclosure+" "+managed.ReusableDisclosure || m.Version != "tracebolt.windows-managed-msi-endpoint-plan.v3") || m.MutationPlanDigest != "" || m.Offer.Validate() != nil || w.Validate() != nil || w.Version != windowsupdatesetup.Version || w.ScheduleScope != "" || w.MutationPlanDigest != "" || m.Observer != w.Observer || lanclient.WindowsUpdateSetupIdentity(m.Identity) != w.Identity || bytes.Equal(m.Offer.ManagerPublicKey, w.Offer.ManagerPublicKey) || m.Artifact.Architecture != "amd64" || w.Artifact.Architecture != "amd64" {
		return managed.ErrAuthority
	}
	return nil
}
func (p coordinatedMutationPlan) FencePlan() fence.Plan {
	digest := func(v any) string { b, _ := json.Marshal(v); return managed.Digest(b) }
	b := p.MSI.Offer
	v := ""
	if p.Version == reusableMutationVersion {
		v = fence.ReusablePlanVersion
	}
	return fence.Plan{Version: v, Identity: fence.Identity{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest}, PlanDigest: p.Digest(), MSIOfferDigest: digest(p.MSI.Offer), WUAOfferDigest: digest(p.WUA.Offer), MSIArtifactDigest: digest(p.MSI.Artifact), WUAArtifactDigest: digest(p.WUA.Artifact)}
}
func runCoordinatedMutationProvision(ctx context.Context, args []string, out, stderr io.Writer, perform func(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error)) int {
	f := flag.NewFlagSet("coordinated-mutations-provision", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mo := f.String("msi-manager-offer", "", "")
	mi := f.String("msi-service-file", "", "")
	mm := f.String("msi-artifact-manifest", "", "")
	wo := f.String("update-manager-offer", "", "")
	wi := f.String("update-executor-file", "", "")
	wm := f.String("update-artifact-manifest", "", "")
	apply := f.Bool("apply", false, "")
	digest := f.String("approve", "", "")
	ack := f.Bool("acknowledge-coordinated-mutations", false, "")
	delivery := f.Bool("acknowledge-managed-delivery", false, "")
	install := f.Bool("acknowledge-one-managed-install", false, "")
	reusable := f.Bool("acknowledge-reusable-managed-jobs", false, "")
	updates := f.Bool("acknowledge-selected-updates", false, "")
	risk := f.Bool("acknowledge-localsystem-risk", false, "")
	relay := f.Bool("acknowledge-observer-relay", false, "")
	query := f.Bool("acknowledge-observer-process-query", false, "")
	if f.Parse(args) != nil || f.NArg() != 0 || ctx == nil || perform == nil || *mo == "" || *mi == "" || *mm == "" || *wo == "" || *wi == "" || *wm == "" || *apply != (*digest != "") || *ack != *apply || *delivery != *apply || (*install || *reusable) != *apply || *install && *reusable || *updates != *apply || *risk != *apply || *relay != *apply || *query != *apply {
		fmt.Fprintln(stderr, "Use --coordinated-mutations-provision with both --msi-manager-offer, --msi-service-file, --msi-artifact-manifest and --update-manager-offer, --update-executor-file, --update-artifact-manifest. Review is read-only. Apply requires --apply --approve <exact review digest> and all acknowledgements: coordinated-mutations, managed-delivery, one-managed-install, selected-updates, localsystem-risk, observer-relay, observer-process-query.")
		return 2
	}
	var input coordinatedMutationInput
	input.Apply = *apply
	input.Digest = *digest
	raw, e := readSoftwareSetupInput(*mo, 16384)
	if e != nil {
		return 1
	}
	input.MSI.offer, e = managed.DecodeSetupOffer(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil || *apply && (input.MSI.offer.Version == managed.ReusableOfferVersion) != *reusable {
		return 1
	}
	raw, e = readUpdateSetupInput(*wo, 16384)
	if e != nil {
		return 1
	}
	input.WUA.offer, e = job.DecodeSetupOffer(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return 1
	}
	for _, item := range []struct {
		manifest, image string
		artifact        *windowspackage.Manifest
		payload         *[]byte
	}{{*mm, *mi, &input.MSI.artifact, &input.MSI.payload}, {*wm, *wi, &input.WUA.artifact, &input.WUA.payload}} {
		raw, e = readUpdateSetupInput(item.manifest, 4096)
		if e != nil {
			return 1
		}
		*item.artifact, e = windowspackage.ParseManifest(raw)
		if e != nil || item.artifact.Architecture != "amd64" {
			return 1
		}
		*item.payload, e = readUpdateSetupInput(item.image, windowspackage.MaxPayloadBytes)
		if e != nil || item.artifact.Validate(*item.payload) != nil {
			return 1
		}
	}
	fmt.Fprintln(stderr, coordinatedMutationDisclosure)
	if input.MSI.offer.Version == managed.ReusableOfferVersion {
		fmt.Fprintln(stderr, managed.ReusableDisclosure)
	}
	result, e := perform(ctx, input)
	if e != nil {
		fmt.Fprintln(stderr, "Coordinated setup is unconfirmed. Preserve all partial state; neither participant may activate. Do not retry, adopt or reset it.")
		return 1
	}
	if *apply {
		if result.MSI.Validate() != nil || result.WUA.Validate() != nil || !managed.ValidDigest(result.FenceDigest) || !managed.ValidDigest(result.MSIConfigDigest) {
			return 1
		}
		if json.NewEncoder(out).Encode(result) != nil {
			return 1
		}
		fmt.Fprintln(stderr, "Both exact participants are bound. Deployment service stays disabled and the observer stays stopped. Finalize both manager registrations, then explicitly start the observer and separately activate the MSI service or launch the WUA foreground executor.")
	} else {
		if result.Plan.Validate() != nil || json.NewEncoder(out).Encode(result.Plan) != nil {
			return 1
		}
		fmt.Fprintln(stderr, "Review digest:", result.Plan.Digest())
	}
	return 0
}
