//go:build windows

package windowsupdateservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"localrmm/internal/lanclient"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateexecutor"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
	"time"
)

func Run(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return job.ErrAuthority
	}
	isService, e := svc.IsWindowsService()
	if e != nil || !isService {
		return job.ErrAuthority
	}
	v := windows.RtlGetVersion()
	if v == nil || v.ProductType == 2 {
		return job.ErrAuthority
	}
	if e = windowsupdateexecutor.VerifyServiceContext(); e != nil {
		return e
	}
	h := &handler{ctx: ctx}
	if e = svc.Run(windowsupdateipc.ServiceName, h); e != nil {
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	checkpoint := uint32(1)
	for {
		select {
		case <-ticker.C:
			if stopping {
				checkpoint++
				status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 30000}
			}
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
	if windowsupdateexecutor.VerifyServiceContext() != nil {
		return job.ErrAuthority
	}
	root, e := windowsupdateipc.ServiceRootPath()
	if e != nil {
		return e
	}
	store, e := windowsstate.Open(root, windowsupdateipc.ServiceStoreOptions())
	if e != nil {
		return e
	}
	defer store.Close()
	raw, e := store.Read("config.json")
	if e != nil {
		return e
	}
	config, e := windowsupdateipc.DecodeConfig(raw)
	if e != nil || config.Version != windowsupdateipc.ServiceConfigVersion || windowsupdatesetup.VerifyInstalled(store, config) != nil {
		return job.ErrAuthority
	}
	if e = CheckProfile(ctx, config); e != nil {
		return e
	}
	if e = VerifyActivation(store, config); e != nil {
		return e
	}
	if e = CheckInstalled(ctx, config, true); e != nil {
		return e
	}
	mutation, e := fence.Open(ctx, *config.Mutation, fence.CachedWUA, time.Now)
	if e != nil {
		return e
	}
	defer mutation.Close()
	guard, e := windowsupdateipc.OpenServiceGuard(ctx, config, config.ObserverProcessQueryAcknowledged)
	if e != nil {
		return e
	}
	defer guard.Close()
	check := func(c context.Context) error {
		if ctx.Err() != nil || c == nil || c.Err() != nil || windowsupdateexecutor.VerifyServiceContext() != nil || guard.Check(c) != nil || CheckInstalled(c, config, true) != nil || CheckProfile(c, config) != nil || store.Verify() != nil || windowsupdatesetup.VerifyInstalled(store, config) != nil || VerifyActivation(store, config) != nil {
			return job.ErrAuthority
		}
		current, e := store.Read("config.json")
		if e != nil || !bytes.Equal(raw, current) {
			return job.ErrIntegrity
		}
		want, _ := json.Marshal(config.Consent)
		for _, name := range []string{"started.json", "receipt.json"} {
			b, e := store.Read(name)
			if e != nil || !bytes.Equal(b, want) {
				return job.ErrIntegrity
			}
		}
		receipt, e := store.Read("progress.json")
		if e != nil {
			return e
		}
		return mutation.VerifyParticipant(c, jobDigest(raw), jobDigest(receipt))
	}
	authority, e := lanclient.OpenWindowsUpdatePublicAuthority(config, check)
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
	if canonical(keyRaw, &material) != nil || material.Version != windowsupdatesetup.BackgroundKeyVersion {
		return job.ErrIntegrity
	}
	defer clear(material.Key)
	adapter := windowsupdateexecutor.New()
	// Join the kernel worker first, then drain COM while protected image, store
	// and shared-fence handles remain held. Late replies cannot rewrite outcomes.
	// Service cancellation closes IPC admission immediately, but waits indefinitely
	// for the actual native owner thread before allowing SCM stopped/process exit.
	defer func() { adapter.StopAdmission(); _ = adapter.Drain(context.Background()) }()
	x, e := job.OpenCoordinatedExecutor(store, authority, adapter, ed25519.PrivateKey(material.Key), time.Now, mutation)
	if e != nil {
		return e
	}
	defer x.Close()
	recordRaw, e := store.Read("executor.json")
	if e != nil {
		return e
	}
	var record job.ExecutorRecord
	if json.Unmarshal(recordRaw, &record) != nil || record.Consent != config.Consent || record.Mutation == nil || *record.Mutation != *config.Mutation || !bytes.Equal(record.PublicKey, config.ManagerPublicKey) || !bytes.Equal(record.ExecutorPublicKey, config.ExecutorPublicKey) {
		return job.ErrIntegrity
	}
	peer, e := config.Peer()
	if e != nil {
		return e
	}
	server, e := windowsupdateipc.NewServer(ctx, x, peer, ed25519.PrivateKey(material.Key), check)
	if e != nil {
		return e
	}
	defer server.Close()
	clear(material.Key)
	ready()
	e = windowsupdateipc.Serve(ctx, server)
	adapter.StopAdmission()
	return e
}
