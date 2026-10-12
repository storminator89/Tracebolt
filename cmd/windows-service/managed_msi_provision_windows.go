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
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		check := func() (lanclient.WindowsManagedMSISetupIdentity, error) {
			if ctx.Err() != nil || lease.Verify() != nil {
				return lanclient.WindowsManagedMSISetupIdentity{}, managed.ErrAuthority
			}
			snap, e := windowsservice.InspectOwned(ctx, receipt.Service)
			if e != nil || snap.State != windowsservice.Stopped || windowspackage.CheckManagedMSIExclusive(ctx) != nil {
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
		p := managedMSIPlan{"tracebolt.windows-managed-msi-endpoint-plan.v1", in.offer, in.artifact, identity, receipt.Service, managed.DeliveryDisclosure, managed.InstallDisclosure, managed.ServiceDisclosure, lanclient.WindowsManagedMSIRelayDisclosure}
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
		if e = windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
			return nil, e
		}
		if !in.apply {
			return nil, nil
		}
		if in.digest != p.Digest() {
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
		if e = write("setup-intent.json", intent); e != nil {
			return nil, e
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
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
		g := managed.Grant{Version: managed.GrantVersion, Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: in.offer.ExpiresAt}
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
		if c.Validate() != nil {
			return nil, managed.ErrInvalid
		}
		if e = write("config.json", c); e != nil {
			return nil, e
		}
		record, e := managed.NewEndpointRecord(g, in.offer.ManagerPublicKey, pub, time.Now().UTC().Unix())
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
		raw, _ := json.Marshal(c)
		complete := windowsmanagedmsiservice.SetupReceipt{Version: windowsmanagedmsiservice.SetupVersion, PlanDigest: p.Digest(), ConfigDigest: managed.Digest(raw), Registration: registration, Image: imageReceipt, ServiceMarker: windowsmanagedmsiservice.Marker(c), Complete: true}
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
	})
	return result, err
}
func nativeManagedMSIActivate(ctx context.Context, digest string) error {
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
	intent := struct {
		Version      string `json:"version"`
		ConfigDigest string `json:"configDigest"`
		Acknowledged bool   `json:"acknowledged"`
	}{managed.Version, digest, true}
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
