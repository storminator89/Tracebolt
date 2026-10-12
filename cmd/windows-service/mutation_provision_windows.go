//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/windows"
	"localrmm/internal/lanclient"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"localrmm/internal/windowsmanagedmsiservice"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdateservice"
	"localrmm/internal/windowsupdatesetup"
	"path/filepath"
	"runtime"
	"time"
)

// One stopped-observer receipt lease covers both reviewed offers/artifacts and
// every staged side effect. The shared create-only intent precedes both keys.
func nativeCoordinatedMutationProvision(ctx context.Context, in coordinatedMutationInput) (out coordinatedMutationResult, err error) {
	if v := windows.RtlGetVersion(); ctx == nil || runtime.GOARCH != "amd64" || v == nil || v.ProductType == 2 {
		return out, managed.ErrAuthority
	}
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		var m managedMSIResult
		var w updateProvisionResult
		// Caller cannot inject already generated material or a nested apply.
		if in.MSI.apply || in.WUA.apply || in.MSI.coordinated != nil || in.WUA.coordinated != nil {
			return nil, managed.ErrAuthority
		}
		if _, e := nativeManagedMSIProvisionUnderLease(ctx, in.MSI, &m, receipt, lease); e != nil {
			return nil, e
		}
		if _, e := nativeUpdateProvisionUnderLease(ctx, in.WUA, &w, receipt, lease); e != nil {
			return nil, e
		}
		plan := coordinatedMutationPlan{Version: coordinatedMutationVersion, MSI: m.plan, WUA: w.plan, Disclosure: coordinatedMutationDisclosure}
		if in.MSI.offer.Version == managed.ReusableOfferVersion {
			plan.Version = reusableMutationVersion
			plan.Disclosure += " " + managed.ReusableDisclosure
		}
		if in.WUA.background {
			plan.Version = backgroundMutationVersion
			plan.Disclosure = windowsupdatesetup.BackgroundDisclosure + " " + managed.ReusableDisclosure
		}
		if plan.Validate() != nil {
			return nil, managed.ErrAuthority
		}
		out.Plan = plan
		if !in.Apply {
			return nil, nil
		}
		if in.Digest != plan.Digest() {
			return nil, managed.ErrAuthority
		}
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		check := func() error {
			if ctx.Err() != nil || lease.Verify() != nil {
				return managed.ErrAuthority
			}
			observer, e := windowsservice.InspectOwned(ctx, receipt.Service)
			if e != nil || observer.State != windowsservice.Stopped {
				return managed.ErrAuthority
			}
			mi, e := lanclient.InspectWindowsManagedMSISetupIdentity(path, in.MSI.offer)
			if e != nil || mi != plan.MSI.Identity {
				return managed.ErrAuthority
			}
			wi, e := lanclient.InspectWindowsUpdateSetupIdentity(path, in.WUA.offer)
			if e != nil || wi != plan.WUA.Identity {
				return managed.ErrAuthority
			}
			return ctx.Err()
		}
		if e := check(); e != nil {
			return nil, e
		}
		fenceID, e := fence.BeginSetup(ctx, plan.FencePlan(), time.Now().UTC().Unix())
		if e != nil {
			return nil, e
		}
		mPub, mKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		defer clear(mKey)
		wPub, wKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		defer clear(wKey)
		var ids [80]byte
		if _, e = rand.Read(ids[:]); e != nil {
			return nil, e
		}
		id := func(prefix string, start int) string { return prefix + hex.EncodeToString(ids[start:start+16]) }
		b := managed.Binding{ManagerID: in.MSI.offer.ManagerID, DeviceID: in.MSI.offer.DeviceID, IncarnationDigest: in.MSI.offer.IncarnationDigest, ExecutorID: id("executor_", 0), ExecutorKeyID: managed.Digest(mPub), KeyID: managed.Digest(in.MSI.offer.ManagerPublicKey), DeliveryGrantID: id("grant_", 16), InstallGrantID: id("grant_", 32)}
		g := managed.Grant{Version: managed.CoordinatedGrantVersion, MutationPlanDigest: plan.Digest(), Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: in.MSI.offer.ExpiresAt}
		if in.MSI.offer.Version == managed.ReusableOfferVersion {
			g.Version = managed.ReusableGrantVersion
			g.ReusableAcknowledged = true
		}
		wb := job.Binding{ManagerID: in.WUA.offer.ManagerID, DeviceID: in.WUA.offer.DeviceID, IncarnationDigest: in.WUA.offer.IncarnationDigest, ExecutorID: id("executor_", 48), ExecutorKeyID: managed.Digest(wPub), KeyID: managed.Digest(in.WUA.offer.ManagerPublicKey), GrantID: id("grant_", 64)}
		consent := job.Consent{Version: job.CoordinatedConsentVersion, MutationPlanDigest: plan.Digest(), Scope: job.Scope, Binding: wb, Enabled: true, Acknowledged: true, ExpiresAt: in.WUA.offer.ExpiresAt}
		if in.WUA.background {
			consent.Version = job.BackgroundConsentVersion
			consent.BackgroundAcknowledged = true
		}
		mbJSON, _ := json.Marshal(b)
		wbJSON, _ := json.Marshal(wb)
		g.PeerBindingDigest = managed.Digest(wbJSON)
		consent.PeerBindingDigest = managed.Digest(mbJSON)
		roster := fence.Roster{Plan: plan.FencePlan(), FenceID: fenceID, MSI: managed.MutationParticipant(g), WUA: job.MutationParticipant(consent)}
		if g.Version == managed.ReusableGrantVersion {
			roster.Version = fence.ReusableRosterVersion
			if in.WUA.background {
				roster.Version = fence.BackgroundRosterVersion
			}
		}
		if g.Validate() != nil || consent.Validate() != nil || roster.Validate() != nil || b.ExecutorKeyID == plan.MSI.Identity.LeafPublicKeyDigest || wb.ExecutorKeyID == plan.MSI.Identity.LeafPublicKeyDigest {
			return nil, managed.ErrAuthority
		}
		if e = check(); e != nil {
			return nil, e
		}
		if e = fence.BindRoster(ctx, roster, time.Now().UTC().Unix()); e != nil {
			return nil, e
		}
		mi := in.MSI
		mi.apply = true
		mi.digest = plan.Digest()
		mi.coordinated = &coordinatedMSIMaterial{roster, mKey, g}
		if _, e = nativeManagedMSIProvisionUnderLease(ctx, mi, &m, receipt, lease); e != nil {
			return nil, e
		}
		wi := in.WUA
		wi.apply = true
		wi.approval = windowsupdatesetup.Approval{Digest: plan.Digest(), Install: true, Relay: true, ProcessQuery: true, Background: in.WUA.background}
		wi.coordinated = &windowsupdatesetup.CoordinatedMaterial{Roster: roster, Key: wKey, ExecutorID: wb.ExecutorID, GrantID: wb.GrantID}
		if _, e = nativeUpdateProvisionUnderLease(ctx, wi, &w, receipt, lease); e != nil {
			return nil, e
		}
		if e = check(); e != nil {
			return nil, e
		}
		activation, e := verifyCoordinatedParticipants(ctx, receipt, roster, path)
		if e != nil {
			return nil, e
		}
		if e = check(); e != nil {
			return nil, e
		}
		if e = fence.Activate(ctx, roster, activation, time.Now().UTC().Unix()); e != nil {
			return nil, e
		}
		out.MSI = m.registration
		out.WUA = w.registration
		if in.WUA.background {
			out.WUAConfigDigest = activation.WUAConfigDigest
		}
		out.MSIConfigDigest = m.configDigest
		out.FenceDigest = roster.Digest()
		return nil, nil
	})
	if err != nil {
		out.MSI = managed.SetupRegistration{}
		out.WUA = job.SetupRegistration{}
		out.MSIConfigDigest = ""
		out.FenceDigest = ""
	}
	return
}

func verifyCoordinatedParticipants(ctx context.Context, receipt installReceipt, roster fence.Roster, path string) (fence.Activation, error) {
	var out fence.Activation
	mroot, e := windowsmanagedmsiipc.RootPath()
	if e != nil {
		return out, e
	}
	ms, e := windowsstate.Open(mroot, windowsmanagedmsiipc.StoreOptions())
	if e != nil {
		return out, e
	}
	defer ms.Close()
	mraw, e := ms.Read("config.json")
	if e != nil {
		return out, e
	}
	mc, e := windowsmanagedmsiipc.DecodeConfig(mraw)
	if e != nil || mc.Mutation == nil || *mc.Mutation != roster || mc.ObserverReceipt != receipt.Service {
		return out, managed.ErrAuthority
	}
	mr, e := windowsmanagedmsiservice.VerifySetup(ms, mc)
	if e != nil {
		return out, e
	}
	mreceipt, e := ms.Read("setup-receipt.json")
	if e != nil {
		return out, e
	}
	if windowsmanagedmsiservice.CheckInstalled(ctx, mc, false) != nil {
		return out, managed.ErrAuthority
	}
	mi, e := windowspackage.OpenManagedMSIServiceImage(ctx, receipt.Service)
	if e != nil {
		return out, e
	}
	e = mi.Verify(ctx, mr.Image)
	ce := mi.Close()
	if e != nil || ce != nil {
		return out, managed.ErrAuthority
	}
	mpeer, e := mc.Peer()
	if e != nil {
		return out, e
	}
	mg := lanclient.WindowsManagedMSIRelayGrant{Version: lanclient.WindowsManagedMSIRelayGrantVersion, Scope: lanclient.WindowsManagedMSIRelayScope, Enabled: true, Acknowledged: true, SenderBinding: mc.SenderBinding, ManagerOrigin: mc.ManagerOrigin, Binding: mc.Grant.Binding, ManagerPublicKey: mc.ManagerPublicKey, ExecutorPublicKey: mc.ExecutorPublicKey, ExecutorPeer: mpeer, ExpiresAt: mc.Grant.ExpiresAt}
	if lanclient.VerifyWindowsManagedMSIRelaySetup(path, mg) != nil {
		return out, managed.ErrAuthority
	}
	rootFunc := windowsupdateipc.RootPath
	options := windowsupdateipc.StoreOptions()
	imageFunc := windowspackage.OpenUpdateExecutorImage
	if roster.Version == fence.BackgroundRosterVersion {
		rootFunc = windowsupdateipc.ServiceRootPath
		options = windowsupdateipc.ServiceStoreOptions()
		imageFunc = windowspackage.OpenUpdateServiceImage
	}
	wroot, e := rootFunc()
	if e != nil {
		return out, e
	}
	ws, e := windowsstate.Open(wroot, options)
	if e != nil {
		return out, e
	}
	defer ws.Close()
	wraw, e := ws.Read("config.json")
	if e != nil {
		return out, e
	}
	wc, e := windowsupdateipc.DecodeConfig(wraw)
	if e != nil || wc.Mutation == nil || *wc.Mutation != roster || wc.ObserverReceipt != receipt.Service || windowsupdatesetup.VerifyInstalled(ws, wc) != nil {
		return out, managed.ErrAuthority
	}
	if roster.Version == fence.BackgroundRosterVersion && windowsupdateservice.CheckInstalled(ctx, wc, false) != nil {
		return out, managed.ErrAuthority
	}
	wreceipt, e := ws.Read("progress.json")
	if e != nil {
		return out, e
	}
	var progress windowsupdatesetup.Progress
	if managed.Canonical(wreceipt, &progress, job.MaxBytes) != nil || progress.Image == nil {
		return out, managed.ErrIntegrity
	}
	planRaw, e := ws.Read("provision.json")
	var plan windowsupdatesetup.Plan
	if e != nil || managed.Canonical(planRaw, &plan, job.MaxBytes) != nil {
		return out, managed.ErrIntegrity
	}
	wi, e := imageFunc(ctx, receipt.Service)
	if e != nil {
		return out, e
	}
	e = wi.Verify(ctx, *progress.Image)
	ce = wi.Close()
	if e != nil || ce != nil {
		return out, managed.ErrAuthority
	}
	wg, e := windowsupdatesetup.Relay(plan, wc)
	if e != nil || lanclient.VerifyWindowsUpdateRelaySetup(path, wg) != nil {
		return out, managed.ErrAuthority
	}
	if bytes.Equal(mc.ExecutorPublicKey, wc.ExecutorPublicKey) || ms.Verify() != nil || ws.Verify() != nil || ms.Close() != nil || ws.Close() != nil {
		return out, managed.ErrIntegrity
	}
	out = fence.Activation{MSIReceiptDigest: managed.Digest(mreceipt), MSIConfigDigest: managed.Digest(mraw), WUAReceiptDigest: managed.Digest(wreceipt), WUAConfigDigest: managed.Digest(wraw)}
	if roster.Version == fence.ReusableRosterVersion {
		out.Version = fence.ReusableActivationVersion
	}
	if roster.Version == fence.BackgroundRosterVersion {
		out.Version = fence.BackgroundActivationVersion
	}
	return out, out.Validate()
}
