//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io/fs"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"localrmm/internal/windowsmanagedmsiservice"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"path/filepath"
	"runtime"
	"time"
)

func nativeManagedMSIProvision(ctx context.Context, in managedMSIInput) (result managedMSIResult, err error) {
	if v := windows.RtlGetVersion(); runtime.GOARCH != "amd64" || v == nil || v.ProductType == 2 {
		return result, managed.ErrAuthority
	}
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		return nativeManagedMSIProvisionUnderLease(ctx, in, &result, receipt, lease)
	})
	return result, err
}

func nativeManagedMSIProvisionUnderLease(ctx context.Context, in managedMSIInput, result *managedMSIResult, receipt installReceipt, lease receiptStore) (any, error) {
	path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
	profile := func() error {
		if in.coordinated == nil {
			return windowspackage.CheckManagedMSIExclusive(ctx)
		}
		exclusive := windowspackage.CheckCoordinatedMutationExclusive
		if in.coordinated.Roster.Version == fence.BackgroundRosterVersion {
			exclusive = windowspackage.CheckBackgroundMutationExclusive
		}
		if e := exclusive(ctx); e != nil {
			return e
		}
		return fence.VerifyStaged(ctx, in.coordinated.Roster)
	}
	check := func() (lanclient.WindowsManagedMSISetupIdentity, error) {
		if ctx.Err() != nil || lease.Verify() != nil {
			return lanclient.WindowsManagedMSISetupIdentity{}, managed.ErrAuthority
		}
		snap, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil || snap.State != windowsservice.Stopped || profile() != nil {
			return lanclient.WindowsManagedMSISetupIdentity{}, managed.ErrAuthority
		}
		original, e := bootstrap(receipt.Service.Layout)
		if e != nil || original.Profile != "tls" || original.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || original.ManagerInstanceID != in.offer.ManagerID || original.AgentOrigin != in.offer.ManagerOrigin {
			return lanclient.WindowsManagedMSISetupIdentity{}, managed.ErrAuthority
		}
		return lanclient.InspectWindowsManagedMSISetupIdentity(path, in.offer)
	}
	identity, e := check()
	if e != nil {
		return nil, e
	}
	p := managedMSIPlan{Version: "tracebolt.windows-managed-msi-endpoint-plan.v1", Offer: in.offer, Artifact: in.artifact, Identity: identity, Observer: receipt.Service, DeliveryDisclosure: managed.DeliveryDisclosure, InstallDisclosure: managed.InstallDisclosure, ServiceDisclosure: managed.ServiceDisclosure, RelayDisclosure: lanclient.WindowsManagedMSIRelayDisclosure}
	if in.offer.Version == managed.ReusableOfferVersion {
		p.Version = "tracebolt.windows-managed-msi-endpoint-plan.v3"
		p.DeliveryDisclosure = managed.ReusableDisclosure
		p.InstallDisclosure = managed.ReusableDisclosure
	}
	if in.coordinated != nil {
		p.Version = "tracebolt.windows-managed-msi-endpoint-plan.v2"
		p.MutationPlanDigest = in.coordinated.Roster.Plan.PlanDigest
	}
	if in.offer.Version == managed.ReusableOfferVersion {
		p.Version = "tracebolt.windows-managed-msi-endpoint-plan.v3"
	}
	result.plan = p
	root, e := windowsmanagedmsiipc.RootPath()
	if e != nil {
		return nil, e
	}
	image, e := windowspackage.OpenManagedMSIServiceImage(ctx, receipt.Service)
	if e != nil {
		return nil, e
	}
	defer image.Close()
	if e = image.CheckAbsent(ctx); e != nil {
		return nil, e
	}
	if e = windowsmanagedmsiservice.CheckAbsent(ctx); e != nil {
		return nil, e
	}
	if e = lanclient.CheckWindowsManagedMSIRelayAbsent(path, in.offer); e != nil {
		return nil, e
	}
	checkAbsent := windowspackage.CheckManagedMSIAbsent
	if in.coordinated != nil {
		checkAbsent = windowspackage.CheckManagedMSIParticipantAbsent
	}
	if e = checkAbsent(ctx); e != nil {
		return nil, e
	}
	if !in.apply {
		return nil, nil
	}
	if in.offer.Version == managed.ReusableOfferVersion && in.coordinated == nil {
		return nil, managed.ErrAuthority
	}
	if in.coordinated == nil && in.digest != p.Digest() || in.coordinated != nil && in.digest != in.coordinated.Roster.Plan.PlanDigest {
		return nil, managed.ErrAuthority
	}
	fresh, e := check()
	if e != nil || fresh != identity {
		return nil, managed.ErrAuthority
	}
	options := windowsmanagedmsiipc.StoreOptions()
	options.Create = true
	s, e := windowsstate.Open(root, options)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	// A permanent intent precedes key generation, image/SCM creation, and relay.
	write := func(name string, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		return s.Write(name, b)
	}
	intent := struct {
		Version    string `json:"version"`
		PlanDigest string `json:"planDigest"`
		Attempted  string `json:"attempted"`
	}{windowsmanagedmsiservice.SetupVersion, p.Digest(), "key"}
	if in.coordinated != nil {
		intent.Version = windowsmanagedmsiservice.CoordinatedSetupVersion
		if in.offer.Version == managed.ReusableOfferVersion {
			intent.Version = windowsmanagedmsiservice.ReusableSetupVersion
		}
	}
	if e = write("setup-intent.json", intent); e != nil {
		return nil, e
	}
	var pub ed25519.PublicKey
	var key ed25519.PrivateKey
	if in.coordinated == nil {
		pub, key, e = ed25519.GenerateKey(rand.Reader)
	} else {
		key = append(ed25519.PrivateKey(nil), in.coordinated.Key...)
		if len(key) != ed25519.PrivateKeySize {
			return nil, managed.ErrAuthority
		}
		pub = key.Public().(ed25519.PublicKey)
	}
	if e != nil {
		return nil, e
	}
	defer clear(key)
	var ids [48]byte
	if _, e = rand.Read(ids[:]); e != nil {
		return nil, e
	}
	b := managed.Binding{ManagerID: in.offer.ManagerID, DeviceID: in.offer.DeviceID, IncarnationDigest: in.offer.IncarnationDigest, KeyID: managed.Digest(in.offer.ManagerPublicKey), ExecutorKeyID: managed.Digest(pub), ExecutorID: "executor_" + hex.EncodeToString(ids[:16]), DeliveryGrantID: "grant_" + hex.EncodeToString(ids[16:32]), InstallGrantID: "grant_" + hex.EncodeToString(ids[32:])}
	if b.ExecutorKeyID == identity.LeafPublicKeyDigest || b.KeyID == identity.LeafPublicKeyDigest {
		return nil, managed.ErrAuthority
	}
	if in.offer.Version == managed.ReusableOfferVersion && in.coordinated == nil {
		return nil, managed.ErrAuthority
	}
	g := managed.Grant{Version: managed.GrantVersion, Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: in.offer.ExpiresAt}
	if in.coordinated != nil {
		g = in.coordinated.Grant
		b = g.Binding
		if !managed.ValidMutationRoster(&in.coordinated.Roster, g) || g.ExpiresAt != in.offer.ExpiresAt || b.KeyID != managed.Digest(in.offer.ManagerPublicKey) || b.ExecutorKeyID != managed.Digest(pub) {
			return nil, managed.ErrAuthority
		}
	}
	if e = write("executor-key.json", struct {
		Version string `json:"version"`
		Key     []byte `json:"key"`
	}{managed.Version, key}); e != nil {
		return nil, e
	}
	intent.Attempted = "image"
	if e = write("setup-intent.json", intent); e != nil {
		return nil, e
	}
	imageReceipt, e := image.Create(ctx, in.payload, in.artifact)
	if e != nil {
		return nil, e
	}
	if e = write("image.json", imageReceipt); e != nil {
		return nil, e
	}
	c := windowsmanagedmsiipc.Config{Version: windowsmanagedmsiipc.ConfigVersion, Grant: g, ManagerPublicKey: in.offer.ManagerPublicKey, ExecutorPublicKey: pub, Executable: imageReceipt.Path, ExecutableDigest: imageReceipt.SHA256, ObserverReceipt: receipt.Service, ObserverProcessQueryAcknowledged: true, ObserverConfigDigest: identity.ConfigDigest, SenderBinding: identity.SenderBinding, ManagerOrigin: identity.ManagerOrigin}
	if in.coordinated != nil {
		c.Version = windowsmanagedmsiipc.CoordinatedConfigVersion
		c.Mutation = &in.coordinated.Roster
	}
	if g.Version == managed.ReusableGrantVersion {
		c.Version = windowsmanagedmsiipc.ReusableConfigVersion
	}
	if c.Validate() != nil {
		return nil, managed.ErrInvalid
	}
	if e = write("config.json", c); e != nil {
		return nil, e
	}
	var record managed.EndpointRecord
	if in.coordinated == nil {
		record, e = managed.NewEndpointRecord(g, in.offer.ManagerPublicKey, pub, time.Now().UTC().Unix())
	} else {
		record, e = managed.NewCoordinatedEndpointRecord(g, in.offer.ManagerPublicKey, pub, time.Now().UTC().Unix(), in.coordinated.Roster)
	}
	if e != nil {
		return nil, e
	}
	if e = write("endpoint.json", record); e != nil {
		return nil, e
	}
	intent.Attempted = "disabled-service"
	if e = write("setup-intent.json", intent); e != nil {
		return nil, e
	}
	if fresh, e = check(); e != nil || fresh != identity {
		return nil, managed.ErrAuthority
	}
	if e = windowsmanagedmsiservice.CreateDisabled(ctx, c); e != nil {
		return nil, e
	}
	peer, e := c.Peer()
	if e != nil {
		return nil, e
	}
	relay := lanclient.WindowsManagedMSIRelayGrant{Version: lanclient.WindowsManagedMSIRelayGrantVersion, Scope: lanclient.WindowsManagedMSIRelayScope, Enabled: true, Acknowledged: true, SenderBinding: identity.SenderBinding, ManagerOrigin: identity.ManagerOrigin, Binding: b, ManagerPublicKey: in.offer.ManagerPublicKey, ExecutorPublicKey: pub, ExecutorPeer: peer, ExpiresAt: g.ExpiresAt}
	intent.Attempted = "observer-relay"
	if e = write("setup-intent.json", intent); e != nil {
		return nil, e
	}
	if e = lanclient.InitializeWindowsManagedMSIRelayCreateOnly(path, relay); e != nil {
		return nil, e
	}
	if e = lanclient.VerifyWindowsManagedMSIRelaySetup(path, relay); e != nil {
		return nil, e
	}
	if e = image.Verify(ctx, imageReceipt); e != nil {
		return nil, e
	}
	if e = windowsmanagedmsiservice.CheckInstalled(ctx, c, false); e != nil {
		return nil, e
	}
	if fresh, e = check(); e != nil || fresh != identity {
		return nil, managed.ErrAuthority
	}
	registration := managed.SetupRegistration{Version: managed.SetupRegistrationVersion, Offer: in.offer, Grant: g, ExecutorPublicKey: pub}
	if g.Version == managed.ReusableGrantVersion {
		registration.Version = managed.ReusableRegistrationVersion
	}
	raw, _ := json.Marshal(c)
	complete := windowsmanagedmsiservice.SetupReceipt{Version: windowsmanagedmsiservice.SetupVersion, PlanDigest: p.Digest(), ConfigDigest: managed.Digest(raw), Registration: registration, Image: imageReceipt, ServiceMarker: windowsmanagedmsiservice.Marker(c), Complete: true}
	if in.coordinated != nil {
		complete.Version = windowsmanagedmsiservice.CoordinatedSetupVersion
		if g.Version == managed.ReusableGrantVersion {
			complete.Version = windowsmanagedmsiservice.ReusableSetupVersion
		}
	}
	if e = write("setup-receipt.json", complete); e != nil {
		return nil, e
	}
	if e = s.Verify(); e != nil {
		return nil, e
	}
	if e = s.Close(); e != nil {
		return nil, e
	}
	result.registration = registration
	result.configDigest = complete.ConfigDigest
	return nil, nil
}
func nativeManagedMSIActivate(ctx context.Context, digest string, proof *windowsmanagedmsiservice.BackgroundRegistrationProof) error {
	root, e := windowsmanagedmsiipc.RootPath()
	if e != nil {
		return e
	}
	s, e := windowsstate.Open(root, windowsmanagedmsiipc.StoreOptions())
	if e != nil {
		return e
	}
	defer s.Close()
	raw, e := s.Read("config.json")
	if e != nil || managed.Digest(raw) != digest {
		return managed.ErrAuthority
	}
	c, e := windowsmanagedmsiipc.DecodeConfig(raw)
	if e != nil {
		return e
	}
	if _, e = windowsmanagedmsiservice.VerifySetup(s, c); e != nil {
		return e
	}
	if _, e = s.Read("activation.json"); !errors.Is(e, fs.ErrNotExist) {
		return managed.ErrConflict
	}
	snap, e := windowsservice.InspectOwned(ctx, c.ObserverReceipt)
	if e != nil || snap.State != windowsservice.Running {
		return managed.ErrAuthority
	}
	intent := windowsmanagedmsiservice.Activation{Version: managed.Version, ConfigDigest: digest, Acknowledged: true, Background: proof}
	if c.Mutation != nil && c.Mutation.Version == fence.BackgroundRosterVersion {
		intent.Version = windowsmanagedmsiservice.BackgroundActivationVersion
	}
	if intent.Validate(c) != nil || proof != nil && time.Now().UTC().Unix() >= proof.Registration.Consent.ExpiresAt {
		return managed.ErrAuthority
	}

	b, _ := json.Marshal(intent)
	if e = s.Write("activation.json", b); e != nil {
		return e
	}
	if e = s.Close(); e != nil {
		return e
	}
	return windowsmanagedmsiservice.Activate(ctx, c)
}

func nativeManagedMSIExport(ctx context.Context) (managedMSIResult, error) {
	var out managedMSIResult
	root, e := windowsmanagedmsiipc.RootPath()
	if e != nil {
		return out, e
	}
	s, e := windowsstate.Open(root, windowsmanagedmsiipc.StoreOptions())
	if e != nil {
		return out, e
	}
	defer s.Close()
	raw, e := s.Read("config.json")
	if e != nil {
		return out, e
	}
	c, e := windowsmanagedmsiipc.DecodeConfig(raw)
	if e != nil {
		return out, e
	}
	r, e := windowsmanagedmsiservice.VerifySetup(s, c)
	if e != nil || ctx.Err() != nil {
		return out, managed.ErrIntegrity
	}
	out.registration = r.Registration
	out.configDigest = r.ConfigDigest
	return out, s.Verify()
}
