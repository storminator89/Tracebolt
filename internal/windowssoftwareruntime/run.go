// Package windowssoftwareruntime joins the separately provisioned foreground
// executor, its real local identity fence, and software-only IPC. No observer
// package imports this runtime or its installer adapter.
package windowssoftwareruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowssoftwareexecutor"
	"localrmm/internal/windowssoftwareipc"
	job "localrmm/internal/windowssoftwarejob"
	"localrmm/internal/windowssoftwaresetup"
	"localrmm/internal/windowsstate"
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
func Run(ctx context.Context, allowObserverProcessQuery, exclusiveMaintenance bool) error {
	maintenanceUntil := time.Now().Add(10 * time.Minute)
	if !exclusiveMaintenance || ctx == nil || ctx.Err() != nil || windowssoftwareexecutor.VerifyForegroundContext() != nil {
		return job.ErrAuthority
	}
	root, e := windowssoftwareipc.RootPath()
	if e != nil {
		return e
	}
	store, e := windowsstate.Open(root, windowssoftwareipc.StoreOptions())
	if e != nil {
		return e
	}
	defer store.Close()
	raw, e := store.Read("config.json")
	if e != nil {
		return e
	}
	config, e := windowssoftwareipc.DecodeConfig(raw)
	if e != nil {
		return e
	}
	if windowssoftwaresetup.VerifyInstalled(store, config) != nil {
		return job.ErrAuthority
	}
	peer, e := config.Peer()
	if e != nil {
		return e
	}
	guard, e := windowssoftwareipc.OpenForegroundGuard(ctx, config, allowObserverProcessQuery)
	if e != nil {
		return e
	}
	defer guard.Close()
	check := func(c context.Context) error {
		if c == nil || c.Err() != nil || windowssoftwareexecutor.VerifyForegroundContext() != nil || guard.Check(c) != nil || store.Verify() != nil || windowssoftwaresetup.VerifyInstalled(store, config) != nil {
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
	authority, e := lanclient.OpenWindowsSoftwareExecutorAuthority(peer, check)
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
	if e != nil || !bytes.Equal(canonical, keyRaw) || material.Version != "tracebolt.windows-software-executor-key.v1" {
		clear(canonical)
		return job.ErrIntegrity
	}
	clear(canonical)
	packageRaw, e := store.Read("package.json")
	var receipt windowspackage.PreparedMSIReceipt
	if e != nil || json.Unmarshal(packageRaw, &receipt) != nil || receipt.Validate() != nil || receipt.Package != config.Consent.Package {
		return job.ErrIntegrity
	}
	adapter, e := windowssoftwareexecutor.New(config.Consent, receipt, maintenanceUntil)
	if e != nil {
		return e
	}
	x, e := job.OpenExecutor(store, authority, adapter, ed25519.PrivateKey(material.Key), time.Now)
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
	server, e := windowssoftwareipc.NewServer(ctx, x, peer, ed25519.PrivateKey(material.Key), check)
	if e != nil {
		return e
	}
	defer server.Close()
	clear(material.Key)
	return windowssoftwareipc.Serve(ctx, server)
}
