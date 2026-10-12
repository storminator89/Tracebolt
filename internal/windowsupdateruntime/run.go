// Package windowsupdateruntime joins the separately provisioned foreground
// executor, its real local identity fence, and update-only IPC. No observer
// package imports this runtime or its installer adapter.
package windowsupdateruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateexecutor"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
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
		if c == nil || c.Err() != nil || windowsupdateexecutor.VerifyForegroundContext() != nil || guard.Check(c) != nil || store.Verify() != nil {
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
	x, e := job.OpenExecutor(store, authority, windowsupdateexecutor.New(), ed25519.PrivateKey(material.Key), time.Now)
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
	if json.Unmarshal(recordRaw, &record) != nil || record.Consent != config.Consent || !bytes.Equal(record.PublicKey, config.ManagerPublicKey) || !bytes.Equal(record.ExecutorPublicKey, config.ExecutorPublicKey) {
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
