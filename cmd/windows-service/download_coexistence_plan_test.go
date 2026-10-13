package main

import (
	"context"
	"io"
	"testing"

	managed "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
)

func coexistencePlanFixture(t *testing.T, wua, msi bool) coordinatedMutationPlan {
	t.Helper()
	p := scheduledMSIPairedPlanFixture(t, false)
	p.Version = downloadCoexistenceMutationVersion
	if !msi {
		p.MSI.Version = "tracebolt.windows-managed-msi-endpoint-plan.v3"
		p.MSI.Offer.Version = managed.ReusableOfferVersion
		p.MSI.ScheduledDisclosure = ""
	}
	var err error
	p.WUA, err = windowsupdatesetup.NewDownloadCoexistenceBackgroundPlan(p.WUA.Offer, p.WUA.Artifact, p.WUA.Identity, p.WUA.Observer, wua)
	if err != nil {
		t.Fatal(err)
	}
	p.Disclosure = windowsupdatesetup.DownloadCoexistenceBackgroundDisclosure + " " + job.DownloadDisclosure + " " + managed.ReusableDisclosure
	if wua {
		p.Disclosure += " " + windowsupdatesetup.DownloadCoexistenceScheduleDisclosure
	}
	if msi {
		p.Disclosure += " " + managed.ScheduledDisclosure
	}
	return p
}

func TestDownloadCoexistencePairPinsEachIndependentScheduler(t *testing.T) {
	for _, flags := range [][2]bool{{true, false}, {false, true}, {true, true}} {
		p := coexistencePlanFixture(t, flags[0], flags[1])
		if p.Validate() != nil || p.FencePlan().Validate() != nil || p.FencePlan().Version != fence.ReusableWUAPlanVersion {
			t.Fatal("fresh combined profile rejected", flags)
		}
		for _, change := range []func(*coordinatedMutationPlan){
			func(p *coordinatedMutationPlan) { p.Version = downloadWUAMutationVersion },
			func(p *coordinatedMutationPlan) { p.WUA.Version = windowsupdatesetup.DownloadBackgroundVersion },
			func(p *coordinatedMutationPlan) { p.Disclosure = windowsupdatesetup.DownloadBackgroundDisclosure },
			func(p *coordinatedMutationPlan) { p.WUA.DownloadDisclosure = "" },
			func(p *coordinatedMutationPlan) {
				p.WUA.ScheduleScope = job.ScheduleScope
				p.WUA.ScheduleDisclosure = ""
			},
		} {
			bad := p
			change(&bad)
			if bad.Validate() == nil || bad.Digest() == p.Digest() {
				t.Fatal("mixed combined review admitted", flags)
			}
		}
		if (p.WUA.ScheduleScope != "") != flags[0] || p.MSI.Offer.Scheduled() != flags[1] {
			t.Fatal("peer scheduler implied independent scope")
		}
	}
	if coexistencePlanFixture(t, false, false).Validate() == nil {
		t.Fatal("combined version silently selected without scheduling")
	}
}

func TestDownloadCoexistenceCLIRequiresEverySelectedAcknowledgement(t *testing.T) {
	base := []string{"--msi-manager-offer", "missing.json", "--msi-service-file", "m.exe", "--msi-artifact-manifest", "m.json", "--update-manager-offer", "w.json", "--update-executor-file", "w.exe", "--update-artifact-manifest", "w.json", "--background-updates", "--reusable-update-jobs", "--allow-update-downloads"}
	never := func(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error) {
		t.Fatal("fixture files unexpectedly reached setup")
		return coordinatedMutationResult{}, nil
	}
	ack := []string{"--apply", "--approve", "sha256:review", "--acknowledge-coordinated-mutations", "--acknowledge-managed-delivery", "--acknowledge-reusable-managed-jobs", "--acknowledge-selected-updates", "--acknowledge-localsystem-risk", "--acknowledge-observer-relay", "--acknowledge-observer-process-query", "--acknowledge-background-updates", "--acknowledge-reusable-update-jobs", "--acknowledge-update-downloads"}
	for _, selected := range [][]string{{"--allow-scheduled-updates"}, {"--allow-scheduled-msi"}, {"--allow-scheduled-updates", "--allow-scheduled-msi"}} {
		review := append(append([]string{}, base...), selected...)
		if code := runCoordinatedMutationProvision(context.Background(), review, io.Discard, io.Discard, never); code != 1 {
			t.Fatal("fresh read-only selection rejected before input read", selected, code)
		}
		all := append(append([]string{}, review...), ack...)
		for _, flag := range selected {
			if flag == "--allow-scheduled-updates" {
				all = append(all, "--acknowledge-scheduled-updates")
			} else {
				all = append(all, "--acknowledge-scheduled-msi")
			}
		}
		if code := runCoordinatedMutationProvision(context.Background(), all, io.Discard, io.Discard, never); code != 1 {
			t.Fatal("complete explicit apply selection rejected before input read", code)
		}
		for i, flag := range all {
			if len(flag) < len("--acknowledge-") || flag[:len("--acknowledge-")] != "--acknowledge-" {
				continue
			}
			missing := append(append([]string{}, all[:i]...), all[i+1:]...)
			if code := runCoordinatedMutationProvision(context.Background(), missing, io.Discard, io.Discard, never); code != 2 {
				t.Fatal("missing combined acknowledgement admitted", flag, code)
			}
		}
	}
}
