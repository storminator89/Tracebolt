package main

import (
	"context"
	"io"
	managed "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
	"testing"
)

func TestDownloadWUAPairedPlanPinsFreshManualScope(t *testing.T) {
	p := scheduledMSIPairedPlanFixture(t, false)
	p.Version = downloadWUAMutationVersion
	p.MSI.Version = "tracebolt.windows-managed-msi-endpoint-plan.v3"
	p.MSI.Offer.Version = managed.ReusableOfferVersion
	p.MSI.ScheduledDisclosure = ""
	var e error
	p.WUA, e = windowsupdatesetup.NewDownloadBackgroundPlan(p.WUA.Offer, p.WUA.Artifact, p.WUA.Identity, p.WUA.Observer)
	if e != nil {
		t.Fatal(e)
	}
	p.Disclosure = windowsupdatesetup.DownloadBackgroundDisclosure + " " + job.DownloadDisclosure + " " + managed.ReusableDisclosure
	if p.Validate() != nil || p.FencePlan().Version != fence.ReusableWUAPlanVersion || p.FencePlan().Validate() != nil {
		t.Fatal("fresh download pair rejected")
	}
	for _, change := range []func(*coordinatedMutationPlan){func(p *coordinatedMutationPlan) { p.Version = reusableWUAMutationVersion }, func(p *coordinatedMutationPlan) { p.WUA.DownloadDisclosure = "" }, func(p *coordinatedMutationPlan) {
		p.Disclosure = windowsupdatesetup.ReusableBackgroundDisclosure + " " + managed.ReusableDisclosure
	}, func(p *coordinatedMutationPlan) { p.MSI.Offer.Version = managed.ScheduledOfferVersion }} {
		bad := p
		change(&bad)
		if bad.Validate() == nil || bad.Digest() == p.Digest() {
			t.Fatal("changed review gained authority")
		}
	}
}
func TestDownloadWUACLIRequiresFreshManualSelectionAndAck(t *testing.T) {
	base := []string{"--msi-manager-offer", "missing.json", "--msi-service-file", "m.exe", "--msi-artifact-manifest", "m.json", "--update-manager-offer", "w.json", "--update-executor-file", "w.exe", "--update-artifact-manifest", "w.json"}
	never := func(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error) {
		t.Fatal("bad inputs reached setup")
		return coordinatedMutationResult{}, nil
	}
	for _, extra := range [][]string{{"--allow-update-downloads"}, {"--background-updates", "--allow-update-downloads"}, {"--background-updates", "--reusable-update-jobs", "--allow-update-downloads", "--acknowledge-update-downloads"}} {
		if code := runCoordinatedMutationProvision(context.Background(), append(append([]string{}, base...), extra...), io.Discard, io.Discard, never); code != 2 {
			t.Fatal("invalid scope accepted", code)
		}
	}
	valid := []string{"--background-updates", "--reusable-update-jobs", "--allow-update-downloads"}
	if code := runCoordinatedMutationProvision(context.Background(), append(base, valid...), io.Discard, io.Discard, never); code != 1 {
		t.Fatal("read-only plan flags not admitted", code)
	}
}
