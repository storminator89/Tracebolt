package main

import (
	"context"
	"io"
	managed "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsupdatesetup"
	"runtime"
	"testing"
)

func TestReusableWUAPairedPlanPinsEveryOptionalScope(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("paired MSI profile is x64 only")
	}
	for _, scheduleWUA := range []bool{false, true} {
		for _, scheduleMSI := range []bool{false, true} {
			p := scheduledMSIPairedPlanFixture(t, scheduleWUA)
			p.Version = reusableWUAMutationVersion
			var e error
			p.WUA, e = windowsupdatesetup.NewReusableBackgroundPlan(p.WUA.Offer, p.WUA.Artifact, p.WUA.Identity, p.WUA.Observer, scheduleWUA)
			if e != nil {
				t.Fatal(e)
			}
			p.Disclosure = windowsupdatesetup.ReusableBackgroundDisclosure + " " + managed.ReusableDisclosure
			if scheduleWUA {
				p.Disclosure += " " + windowsupdatesetup.ReusableBackgroundScheduleDisclosure
			}
			if scheduleMSI {
				p.Disclosure += " " + managed.ScheduledDisclosure
			} else {
				p.MSI.Version = "tracebolt.windows-managed-msi-endpoint-plan.v3"
				p.MSI.Offer.Version = managed.ReusableOfferVersion
				p.MSI.ScheduledDisclosure = ""
			}
			if p.Validate() != nil || p.FencePlan().Validate() != nil || p.FencePlan().Version != fence.ReusableWUAPlanVersion {
				t.Fatal("fresh reusable paired plan rejected")
			}
			for _, change := range []func(*coordinatedMutationPlan){
				func(p *coordinatedMutationPlan) { p.Version = backgroundMutationVersion },
				func(p *coordinatedMutationPlan) { p.Version = scheduledBackgroundMutationVersion },
				func(p *coordinatedMutationPlan) {
					p.Disclosure = windowsupdatesetup.BackgroundDisclosure + " " + managed.ReusableDisclosure
				},
				func(p *coordinatedMutationPlan) {
					p.WUA.Version = windowsupdatesetup.BackgroundVersion
					p.WUA.ProcessQueryDisclosure = windowsupdatesetup.BackgroundDisclosure
				},
				func(p *coordinatedMutationPlan) { p.MSI.Offer.Version = managed.SetupOfferVersion },
			} {
				bad := p
				change(&bad)
				if bad.Validate() == nil || bad.Digest() == p.Digest() {
					t.Fatal("changed profile not bound")
				}
			}
		}
	}
}
func TestReusableWUASetupRequiresSelectedBackgroundAndSeparateAck(t *testing.T) {
	base := []string{"--msi-manager-offer", "missing-msi.json", "--msi-service-file", "m.exe", "--msi-artifact-manifest", "m.manifest.json", "--update-manager-offer", "w.json", "--update-executor-file", "w.exe", "--update-artifact-manifest", "w.manifest.json"}
	apply := []string{"--apply", "--approve", "sha256:fixture", "--acknowledge-coordinated-mutations", "--acknowledge-managed-delivery", "--acknowledge-reusable-managed-jobs", "--acknowledge-selected-updates", "--acknowledge-localsystem-risk", "--acknowledge-observer-relay", "--acknowledge-observer-process-query", "--background-updates", "--acknowledge-background-updates", "--reusable-update-jobs", "--acknowledge-reusable-update-jobs"}
	never := func(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error) {
		t.Fatal("invalid or missing inputs reached native setup")
		return coordinatedMutationResult{}, nil
	}
	for _, missing := range []string{"--background-updates", "--acknowledge-background-updates", "--reusable-update-jobs", "--acknowledge-reusable-update-jobs", "--acknowledge-reusable-managed-jobs", "--acknowledge-selected-updates", "--acknowledge-observer-relay", "--acknowledge-observer-process-query"} {
		args := append([]string{}, base...)
		for _, a := range apply {
			if a != missing {
				args = append(args, a)
			}
		}
		if code := runCoordinatedMutationProvision(context.Background(), args, io.Discard, io.Discard, never); code != 2 {
			t.Fatal("missing independent acknowledgement not rejected before I/O", missing, code)
		}
	}
	for _, extra := range [][]string{{"--reusable-update-jobs"}, {"--background-updates", "--acknowledge-reusable-update-jobs"}, {"--background-updates", "--reusable-update-jobs", "--acknowledge-reusable-update-jobs"}} {
		if code := runCoordinatedMutationProvision(context.Background(), append(append([]string{}, base...), extra...), io.Discard, io.Discard, never); code != 2 {
			t.Fatal("invalid review gained reusable scope", code)
		}
	}
	// Complete syntactic review/apply reaches the missing-input boundary only.
	for _, extra := range [][]string{{"--background-updates", "--reusable-update-jobs"}, apply} {
		if code := runCoordinatedMutationProvision(context.Background(), append(append([]string{}, base...), extra...), io.Discard, io.Discard, never); code != 1 {
			t.Fatal("valid fresh flags not accepted", code)
		}
	}
}
