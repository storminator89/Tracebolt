//go:build windows

package windowsmanagedmsiservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"localrmm/internal/lanclient"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiexecutor"
	"localrmm/internal/windowsmanagedmsiipc"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsstate"
	"time"
)

func Run(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return managed.ErrAuthority
	}
	isService, e := svc.IsWindowsService()
	if e != nil || !isService {
		return managed.ErrAuthority
	}
	v := windows.RtlGetVersion()
	if v == nil || v.ProductType == 2 {
		return managed.ErrAuthority
	}
	if e = windowsmanagedmsiexecutor.VerifyServiceToken(); e != nil {
		return e
	}
	h := &handler{ctx: ctx}
	if e = svc.Run(windowsmanagedmsiipc.ServiceName, h); e != nil {
		return e
	}
	return h.err
}

type handler struct {
	ctx context.Context
	err error
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	status <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30000}
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- run(ctx, func() { close(ready) }) }()
	var readyCh <-chan struct{} = ready
	stopping := false
	parentDone := h.ctx.Done()
	for {
		select {
		case <-readyCh:
			readyCh = nil
			if !stopping {
				status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case <-parentDone:
			parentDone = nil
			stopping = true
			readyCh = nil
			status <- svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000}
			cancel()
		case r, ok := <-requests:
			if !ok {
				requests = nil
				stopping = true
				cancel()
				continue
			}
			switch r.Cmd {
			case svc.Stop, svc.Shutdown:
				if !stopping {
					stopping = true
					readyCh = nil
					status <- svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000}
					cancel()
				}
			case svc.Interrogate:
				status <- r.CurrentStatus
			}
		case e := <-done:
			h.err = e
			if stopping && (e == nil || e == context.Canceled) {
				h.err = nil
				return false, 0
			}
			return true, 1
		}
	}
}
func run(ctx context.Context, ready func()) error {
	if windowsmanagedmsiexecutor.VerifyServiceToken() != nil {
		return managed.ErrAuthority
	}
	root, e := windowsmanagedmsiipc.RootPath()
	if e != nil {
		return e
	}
	store, e := windowsstate.Open(root, windowsmanagedmsiipc.StoreOptions())
	if e != nil {
		return e
	}
	defer store.Close()
	raw, e := store.Read("config.json")
	if e != nil {
		return e
	}
	config, e := windowsmanagedmsiipc.DecodeConfig(raw)
	if e != nil {
		return e
	}
	if e = CheckProfile(ctx, config); e != nil {
		return e
	}
	var mutation *fence.Session
	if config.Mutation != nil {
		mutation, e = fence.Open(ctx, *config.Mutation, fence.ManagedMSI, time.Now)
		if e != nil {
			return e
		}
		defer mutation.Close()
	}
	receipt, e := VerifySetup(store, config)
	if e != nil {
		return e
	}
	activation, e := store.Read("activation.json")
	var intent Activation
	if e != nil || managed.Canonical(activation, &intent, 16384) != nil || intent.Validate(config) != nil || intent.ConfigDigest != receipt.ConfigDigest {
		return managed.ErrAuthority
	}

	if e = CheckInstalled(ctx, config, true); e != nil {
		return e
	}
	guard, e := windowsmanagedmsiipc.OpenServiceGuard(ctx, config, config.ObserverProcessQueryAcknowledged)
	if e != nil {
		return e
	}
	defer guard.Close()
	check := func(c context.Context) error {
		if ctx.Err() != nil || c == nil || c.Err() != nil || windowsmanagedmsiexecutor.VerifyServiceToken() != nil || guard.Check(c) != nil || CheckInstalled(c, config, true) != nil || CheckProfile(c, config) != nil || store.Verify() != nil {
			return managed.ErrAuthority
		}
		if config.Mutation != nil && config.Mutation.Version == fence.BackgroundRosterVersion {
			currentActivation, ae := store.Read("activation.json")
			if ae != nil || !bytes.Equal(currentActivation, activation) {
				return managed.ErrAuthority
			}
		}
		current, e := store.Read("config.json")
		if e != nil || !bytes.Equal(raw, current) {
			return managed.ErrIntegrity
		}
		_, e = VerifySetup(store, config)
		if e == nil && mutation != nil {
			receiptRaw, re := store.Read("setup-receipt.json")
			if re != nil {
				return re
			}
			e = mutation.VerifyParticipant(c, managed.Digest(raw), managed.Digest(receiptRaw))
		}
		return e
	}
	authority, e := lanclient.OpenWindowsManagedMSIPublicAuthority(config, check)
	if e != nil {
		return e
	}
	keyRaw, e := store.Read("executor-key.json")
	if e != nil {
		return e
	}
	defer clear(keyRaw)
	var material struct {
		Version string `json:"version"`
		Key     []byte `json:"key"`
	}
	if managed.Canonical(keyRaw, &material, 4096) != nil || material.Version != managed.Version {
		return managed.ErrIntegrity
	}
	defer clear(material.Key)
	payload := windowspackage.NewManagedMSIPayload()
	var x *managed.Endpoint
	if mutation == nil {
		x, e = managed.OpenEndpoint(store, payload, windowsmanagedmsiexecutor.NewInstaller(), authority, ed25519.PrivateKey(material.Key), time.Now)
	} else {
		x, e = managed.OpenCoordinatedEndpoint(store, payload, windowsmanagedmsiexecutor.NewCoordinatedInstaller(), authority, ed25519.PrivateKey(material.Key), time.Now, mutation)
	}
	if e != nil {
		return e
	}
	defer x.Close()
	defer x.Wait()
	peer, e := config.Peer()
	if e != nil {
		return e
	}
	server, e := windowsmanagedmsiipc.NewServer(ctx, x, peer, ed25519.PrivateKey(material.Key), check)
	if e != nil {
		return e
	}
	defer server.Close()
	clear(material.Key)
	ready()
	return windowsmanagedmsiipc.Serve(ctx, server)
}

// ConfigurationDigest is public review material, never private key material.
func ConfigurationDigest(c windowsmanagedmsiipc.Config) string {
	b, _ := json.Marshal(c)
	return managed.Digest(b)
}
