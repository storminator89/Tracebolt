package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
)

const RemovalVersion = "tracebolt.windows-selected-update-removal.v1"
const RetiredKeyVersion = "tracebolt.windows-update-executor-key-retired.v1"

type RemovalPlan struct {
	Version             string                                    `json:"version"`
	ProvisionDigest     string                                    `json:"provisionDigest"`
	ConfigurationDigest string                                    `json:"configurationDigest"`
	LedgerDigest        string                                    `json:"ledgerDigest"`
	Image               windowspackage.UpdateExecutorImageReceipt `json:"image"`
}

func (p RemovalPlan) Digest() string { b, _ := json.Marshal(p); return actionpermit.Digest(b) }

type removalRecord struct {
	Plan      RemovalPlan `json:"plan"`
	StartedAt int64       `json:"startedAt"`
	Attempted string      `json:"attempted"`
	Completed []string    `json:"completed"`
	Complete  bool        `json:"complete"`
}
type RemovalHooks struct {
	Check       func(context.Context, Plan) error
	VerifyImage func(context.Context, windowspackage.UpdateExecutorImageReceipt) error
	RetireRelay func(context.Context, lanclient.WindowsUpdateRelayGrant) error
	RemoveImage func(context.Context, windowspackage.UpdateExecutorImageReceipt) error
	ImageAbsent func(context.Context) error
}

// InspectRemoval requires the exclusive store lease and no unresolved attempt.
// A held foreground store, partial setup, replaced bytes or removal intent blocks.
func InspectRemoval(s Store) (RemovalPlan, Plan, windowsupdateipc.Config, error) {
	var zero RemovalPlan
	var p Plan
	var c windowsupdateipc.Config
	if s == nil {
		return zero, p, c, ErrSetup
	}
	raw, e := s.Read("config.json")
	if e != nil {
		return zero, p, c, ErrSetup
	}
	c, e = windowsupdateipc.DecodeConfig(raw)
	if e != nil || c.Version == windowsupdateipc.ServiceConfigVersion || VerifyInstalled(s, c) != nil {
		return zero, p, c, ErrSetup
	}
	secret, e := s.Read("executor-key.json")
	var key keyMaterial
	if e != nil || decode(secret, &key) != nil {
		clear(secret)
		clear(key.Key)
		return zero, p, c, ErrSetup
	}
	clear(secret)
	valid := key.Version == KeyVersion && len(key.Key) == ed25519.PrivateKeySize && bytes.Equal(key.Key, ed25519.NewKeyFromSeed(key.Key[:ed25519.SeedSize])) && bytes.Equal(ed25519.PrivateKey(key.Key).Public().(ed25519.PublicKey), c.ExecutorPublicKey)
	clear(key.Key)
	if !valid {
		return zero, p, c, ErrSetup
	}
	configDigest := actionpermit.Digest(raw)
	raw, e = s.Read("provision.json")
	if e != nil || decode(raw, &p) != nil {
		return zero, p, c, ErrSetup
	}
	raw, e = s.Read("progress.json")
	var progress Progress
	if e != nil || decode(raw, &progress) != nil || progress.Image == nil {
		return zero, p, c, ErrSetup
	}
	raw, e = s.Read("executor.json")
	var record job.ExecutorRecord
	if e != nil || decode(raw, &record) != nil || record.Validate() != nil || record.Consent != c.Consent || !bytes.Equal(record.PublicKey, c.ManagerPublicKey) || !bytes.Equal(record.ExecutorPublicKey, c.ExecutorPublicKey) {
		return zero, p, c, ErrSetup
	}
	for _, a := range record.Attempts {
		if a.Result == nil || a.Result.Outcome == "uncertain" || a.Result.Outcome == "failed" {
			return zero, p, c, job.ErrUncertain
		}
	}
	return RemovalPlan{RemovalVersion, p.Digest(), configDigest, actionpermit.Digest(raw), *progress.Image}, p, c, nil
}

// Remove retires only a complete owned installation. It preserves the public
// original consent, all used records, scopes and permanent removal evidence.
// No failure resumes automatically; no unknown file or directory is deleted.
func Remove(ctx context.Context, s Store, approved string, h RemovalHooks) error {
	return remove(ctx, s, approved, h, time.Now)
}
func remove(ctx context.Context, s Store, approved string, h RemovalHooks, now func() time.Time) error {
	if ctx == nil || s == nil || h.Check == nil || h.VerifyImage == nil || h.RetireRelay == nil || h.RemoveImage == nil || h.ImageAbsent == nil || now == nil {
		return ErrSetup
	}
	review, p, c, e := InspectRemoval(s)
	if e != nil || review.Digest() != approved {
		return ErrChanged
	}
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.Verify() != nil {
			return ErrSetup
		}
		return h.Check(ctx, p)
	}
	if guard() != nil || h.VerifyImage(ctx, review.Image) != nil || guard() != nil {
		return ErrSetup
	}
	relay, e := Relay(p, c)
	if e != nil {
		return e
	}
	record := removalRecord{Plan: review, StartedAt: now().UTC().Unix(), Completed: []string{}}
	if record.StartedAt <= 0 {
		return ErrSetup
	}
	save := func() error {
		raw, _ := json.Marshal(record)
		if s.Write("removed.json", raw) != nil {
			return ErrSetup
		}
		return guard()
	}
	// This permanent intent disables the runtime before any cross-store change.
	if e = save(); e != nil {
		return e
	}
	for _, stage := range []string{"retire-relay", "retire-key", "remove-image"} {
		record.Attempted = stage
		if e = save(); e != nil {
			return e
		}
		switch stage {
		case "retire-relay":
			e = h.RetireRelay(ctx, relay)
		case "retire-key":
			raw, _ := json.Marshal(keyMaterial{Version: RetiredKeyVersion})
			e = s.Write("executor-key.json", raw)
		case "remove-image":
			e = h.RemoveImage(ctx, review.Image)
		}
		if e != nil {
			return errors.Join(ErrSetup, e)
		}
		if e = guard(); e != nil {
			return e
		}
		record.Completed = append(record.Completed, stage)
		record.Attempted = ""
		if e = save(); e != nil {
			return e
		}
	}
	if h.ImageAbsent(ctx) != nil {
		return ErrSetup
	}
	record.Complete = true
	if e = save(); e != nil {
		return e
	}
	return VerifyRemoved(s)
}
func VerifyRemoved(s Store) error {
	if s == nil || s.Verify() != nil {
		return ErrSetup
	}
	raw, e := s.Read("removed.json")
	var r removalRecord
	if e != nil || decode(raw, &r) != nil || r.Plan.Version != RemovalVersion || !r.Complete || r.Attempted != "" || !sameJSON(r.Completed, []string{"retire-relay", "retire-key", "remove-image"}) || r.StartedAt <= 0 {
		return ErrSetup
	}
	raw, e = s.Read("provision.json")
	var p Plan
	if e != nil || decode(raw, &p) != nil || p.Validate() != nil || p.Digest() != r.Plan.ProvisionDigest {
		return ErrSetup
	}
	raw, e = s.Read("config.json")
	if e != nil || actionpermit.Digest(raw) != r.Plan.ConfigurationDigest {
		return ErrSetup
	}
	raw, e = s.Read("executor.json")
	if e != nil || actionpermit.Digest(raw) != r.Plan.LedgerDigest {
		return ErrSetup
	}
	raw, e = s.Read("executor-key.json")
	want, _ := json.Marshal(keyMaterial{Version: RetiredKeyVersion})
	if e != nil || !bytes.Equal(raw, want) {
		return ErrSetup
	}
	return s.Verify()
}
