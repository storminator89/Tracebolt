// Package windowsupdateruntime joins the separately provisioned foreground
// executor, its real local identity fence, and update-only IPC. No observer
// package imports this runtime or its installer adapter.
package windowsupdateruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/lanclient"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateexecutor"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
	"time"
)

type privateKey struct {
	Version string `json:"version"`
	Key     []byte `json:"key"`
}

// Run opens ONLY already-provisioned administrator-protected state. It cannot
// initialize, repair, reset, generate keys, enroll, install a service or grant a
// persistent account permission. The optional process-query right expires with
// this explicitly administrator-launched process, and requires BOTH approvals.
func Run(ctx context.Context, allowObserverProcessQuery bool) error {
	if ctx == nil || ctx.Err() != nil || windowsupdateexecutor.VerifyForegroundContext() != nil {
		return job.ErrAuthority
	}
	root, e := windowsupdateipc.RootPath()
	if e != nil {
		return e
	}
	store, e := windowsstate.Open(root, windowsupdateipc.StoreOptions())
	if e != nil {
		return e
	}
	defer store.Close()
	raw, e := store.Read("config.json")
	if e != nil {
		return e
	}
	config, e := windowsupdateipc.DecodeConfig(raw)
	if e != nil {
		return e
	}
	if windowsupdatesetup.VerifyInstalled(store, config) != nil {
		return job.ErrAuthority
	}
	var mutation *fence.Session
	if config.Mutation != nil {
		mutation, e = fence.Open(ctx, *config.Mutation, fence.CachedWUA, time.Now)
		if e != nil {
			return e
		}
		defer mutation.Close()
	}
	profile := func(ctx context.Context) error {
		if mutation == nil {
			return windowspackage.CheckManagedMSIAbsent(ctx)
		}
		if e := windowspackage.CheckCoordinatedMutationExclusive(ctx); e != nil {
			return e
		}
		receipt, re := store.Read("progress.json")
		if re != nil {
			return re
		}
		return mutation.VerifyParticipant(ctx, actionpermit.Digest(raw), actionpermit.Digest(receipt))
	}
	if e = profile(ctx); e != nil {
		return e
	}
	peer, e := config.Peer()
	if e != nil {
		return e
	}
	guard, e := windowsupdateipc.OpenForegroundGuard(ctx, config, allowObserverProcessQuery)
	if e != nil {
		return e
	}
	defer guard.Close()
	check := func(c context.Context) error {
		if c == nil || c.Err() != nil || windowsupdateexecutor.VerifyForegroundContext() != nil || guard.Check(c) != nil || profile(c) != nil || store.Verify() != nil || windowsupdatesetup.VerifyInstalled(store, config) != nil {
			return job.ErrAuthority
		}
		current, e := store.Read("config.json")
		if e != nil || !bytes.Equal(current, raw) {
			return job.ErrAuthority
		}
		want, _ := json.Marshal(config.Consent)
		for _, name := range []string{"started.json", "receipt.json"} {
			b, e := store.Read(name)
			if e != nil || !bytes.Equal(b, want) {
				return job.ErrAuthority
			}
		}
		return c.Err()
	}
	authority, e := lanclient.OpenWindowsUpdateExecutorAuthority(peer, check)
	if e != nil {
		return e
	}
	keyRaw, e := store.Read("executor-key.json")
	if e != nil {
		return e
	}
	defer clear(keyRaw)
	var material privateKey
	d := json.NewDecoder(bytes.NewReader(keyRaw))
	d.DisallowUnknownFields()
	if d.Decode(&material) != nil {
		return job.ErrIntegrity
	}
	defer clear(material.Key)
	canonical, e := json.Marshal(material)
	if e != nil || !bytes.Equal(canonical, keyRaw) || material.Version != "tracebolt.windows-update-executor-key.v1" {
		clear(canonical)
		return job.ErrIntegrity
	}
	clear(canonical)
	var x *job.Executor
	if mutation == nil {
		x, e = job.OpenExecutor(store, authority, windowsupdateexecutor.New(), ed25519.PrivateKey(material.Key), time.Now)
	} else {
		x, e = job.OpenCoordinatedExecutor(store, authority, windowsupdateexecutor.New(), ed25519.PrivateKey(material.Key), time.Now, mutation)
	}
	if e != nil {
		return e
	}
	defer x.Close()
	// Pin the full provisioned ledger to exactly this immutable public config.
	recordRaw, e := store.Read("executor.json")
	if e != nil {
		return e
	}
	var record job.ExecutorRecord
	if json.Unmarshal(recordRaw, &record) != nil || record.Consent != config.Consent || config.Mutation != nil && (record.Mutation == nil || *record.Mutation != *config.Mutation) || !bytes.Equal(record.PublicKey, config.ManagerPublicKey) || !bytes.Equal(record.ExecutorPublicKey, config.ExecutorPublicKey) {
		return job.ErrIntegrity
	}
	server, e := windowsupdateipc.NewServer(ctx, x, peer, ed25519.PrivateKey(material.Key), check)
	if e != nil {
		return e
	}
	defer server.Close()
	clear(material.Key)
	return windowsupdateipc.Serve(ctx, server)
}
