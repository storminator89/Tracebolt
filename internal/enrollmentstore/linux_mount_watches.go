package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/linuxmountwatch"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"sort"
	"time"
)

// WithLinuxMountWatch reads only existing volume generations under the unchanged
// overview authority boundary. The bounded callback must commit before its lease
// expires. It adds no collection, endpoint grant or enrollment acceptance path.
func (s *Store) WithLinuxMountWatch(ctx context.Context, device string, target *linuxmountwatch.Target, epoch string, clock func() time.Time, fn func(linuxmountwatch.Input, func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || !completeProfile(s.config.Binding.CollectionProfile) || !enrollmentcrypto.ValidID(device, "agent_") || len(epoch) != 64 || target != nil && !linuxmountwatch.ValidTarget(*target) {
		return enrollmentstate.ErrInvalid
	}
	key, e := hex.DecodeString(epoch)
	if e != nil || hex.EncodeToString(key) != epoch {
		return enrollmentstate.ErrInvalid
	}
	release, e := s.systemReadAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.transact(ctx, func(t *transaction) error {
		started := clock().UTC()
		if !validStoreTime(started) {
			return enrollmentstate.ErrInvalid
		}
		snap, e := s.overviewOperatorAuthority(t, device, "volumes", started)
		if e != nil {
			return e
		}
		leaf := t.currentCertificateHash(snap)
		raw, _ := json.Marshal(struct {
			Binding                         enrollmentstate.Binding
			Invitation, Device, Certificate string
		}{snap.Binding, snap.InvitationID, device, snap.Issuance.CertificateHash})
		digest := sha256.Sum256(append([]byte("tracebolt.linux-mount-watch.identity.v1\x00"), raw...))
		clear(raw)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(digest[:])
		in := linuxmountwatch.Input{DeviceID: device, Identity: hex.EncodeToString(digest[:]), SourceToken: "mountsource_" + hex.EncodeToString(mac.Sum(nil)[:16]), AuthorityUntil: time.Unix(t.currentCredentialNotAfter(snap), 0).UTC(), Reason: "no_generation", Options: []linuxmountwatch.Target{}}
		sample, reason, e := mountWatchGeneration(ctx, t, snap, started)
		if e != nil {
			return e
		}
		in.Reason = reason
		if sample != nil {
			in.Generation = &sample.Generation
			in.Available = true
			in.Options, in.MoreOptions, in.Sample, e = mountWatchRows(ctx, t, device, *sample, target)
			if e != nil {
				return e
			}
		}
		last := started
		guard := func(minimum time.Time) error {
			at := clock().UTC()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !validStoreTime(at) || at.Before(last) || at.Before(minimum) || at.Sub(started) > 5*time.Second || !at.Before(in.AuthorityUntil) {
				return enrollmentstate.ErrProof
			}
			last = at
			current, e := s.overviewOperatorAuthority(t, device, "volumes", at)
			if e != nil {
				return e
			}
			if current.InvitationID != snap.InvitationID || current.Issuance.CertificateHash != snap.Issuance.CertificateHash || current.Binding != snap.Binding || t.currentCertificateHash(current) != leaf || t.currentCredentialNotAfter(current) != in.AuthorityUntil.Unix() {
				return enrollmentstate.ErrProof
			}
			latest, r, e := mountWatchGeneration(ctx, t, current, at)
			if e != nil {
				return e
			}
			if (latest == nil) != (sample == nil) || r != reason {
				return enrollmentstate.ErrProof
			}
			if latest != nil && (latest.Binding != sample.Binding || latest.Generation != sample.Generation) {
				return enrollmentstate.ErrProof
			}
			return nil
		}
		if e = guard(started); e != nil {
			return e
		}
		if e = fn(in, guard); e != nil {
			return e
		}
		return guard(last)
	})
}

type mountWatchSample struct {
	Generation linuxmountwatch.Generation
	Binding    OverviewBinding
	Manifest   overviewgeneration.Manifest
}

func mountWatchGeneration(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, now time.Time) (*mountWatchSample, string, error) {
	status, e := overviewStatus(ctx, t, snap, "volumes", now)
	if errors.Is(e, overviewledger.ErrNotFound) {
		return nil, "no_generation", nil
	}
	if errors.Is(e, overviewledger.ErrExpired) {
		return nil, "stale", nil
	}
	if e != nil {
		return nil, "", e
	}
	if status.Complete == nil {
		return nil, "no_generation", nil
	}
	c := status.Complete
	b := status.CompleteBinding
	m := c.Manifest
	if status.Sequence != b.Sequence || status.Failure != nil || status.Transfer != nil && (status.Transfer.Manifest.GenerationID != b.GenerationID || status.Transfer.State != "complete") {
		return nil, "newer_attempt", nil
	}
	if c.State != "complete" || m.CaptureStartedAt.After(now) || c.CompletedAt.After(now) || !now.Before(m.CaptureStartedAt.Add(linuxmountwatch.MaxAge)) || !now.Before(c.CompletedAt.Add(linuxmountwatch.MaxAge)) {
		return nil, "stale", nil
	}
	if m.Section != "volumes" || m.Volumes.Coverage != completeoverview.Complete || !m.Volumes.CountExact || m.ObservedCount > completeoverview.MaxVolumeRows || c.AcceptedRows != m.ObservedCount || c.AcceptedChunks != m.ChunkCount {
		return nil, "", ErrStorage
	}
	return &mountWatchSample{linuxmountwatch.Generation{Sequence: b.Sequence, ID: b.GenerationID, CapturedAt: m.CaptureStartedAt, ReceivedAt: c.CompletedAt}, b, m}, "none", nil
}
func mountWatchRows(ctx context.Context, t *transaction, device string, sample mountWatchSample, target *linuxmountwatch.Target) ([]linuxmountwatch.Target, bool, *linuxmountwatch.Sample, error) {
	v, e := overviewgeneration.NewValidator(ctx, sample.Manifest)
	if e != nil {
		return nil, false, nil, ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT ordinal,body FROM co_chunks WHERE device=? AND generation=? ORDER BY ordinal LIMIT 1025`, overviewDevice(device, "volumes"), sample.Binding.GenerationID)
	if e != nil {
		return nil, false, nil, ErrStorage
	}
	defer rows.Close()
	// The complete namespace is scanned before selecting any row. Duplicate mount
	// locations (including overmounts) stay ambiguous even if only one is measured.
	paths := map[string]int{}
	candidates := map[string]linuxmountwatch.Sample{}
	var count uint32
	for rows.Next() {
		var ordinal uint32
		var raw []byte
		if rows.Scan(&ordinal, &raw) != nil || ordinal != count || count >= sample.Manifest.ChunkCount || len(raw) == 0 || len(raw) > overviewgeneration.MaxChunkBytes {
			return nil, false, nil, ErrStorage
		}
		var chunk overviewgeneration.Chunk
		if json.Unmarshal(raw, &chunk) != nil || overviewgeneration.ValidateChunk(chunk) != nil {
			return nil, false, nil, ErrStorage
		}
		canonical, _ := json.Marshal(chunk)
		if !bytes.Equal(canonical, raw) || v.Add(chunk) != nil {
			return nil, false, nil, ErrStorage
		}
		for _, r := range chunk.Items {
			if ctx.Err() != nil {
				return nil, false, nil, ctx.Err()
			}
			p := r.Volume
			if p == nil {
				return nil, false, nil, ErrStorage
			}
			paths[p.MountPoint]++
			t := linuxmountwatch.Target{MountPoint: p.MountPoint, Filesystem: p.Filesystem, FilesystemGroup: p.FilesystemGroup}
			if p.Kind == "local" && p.Measurement.Status == completeoverview.Observed && p.Measurement.Reason == completeoverview.ReasonNone && p.TotalBytes != nil && *p.TotalBytes > 0 && p.AvailableBytes != nil && p.UsedPercent != nil && linuxmountwatch.ValidTarget(t) {
				candidates[p.MountPoint] = linuxmountwatch.Sample{Target: t, MountID: p.ID, UsedPercent: *p.UsedPercent, TotalBytes: *p.TotalBytes, AvailableBytes: *p.AvailableBytes}
			}
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil || count != sample.Manifest.ChunkCount {
		return nil, false, nil, ErrStorage
	}
	proof, e := v.Finish()
	if e != nil || !proof.Valid() || proof.ManifestSHA256() != sample.Binding.ManifestHash {
		return nil, false, nil, ErrStorage
	}
	keys := []string{}
	for path := range candidates {
		if paths[path] == 1 {
			keys = append(keys, path)
		}
	}
	sort.Strings(keys)
	out := []linuxmountwatch.Target{}
	optionBytes := 0
	optionsFull := false
	var selected *linuxmountwatch.Sample
	for _, p := range keys {
		r := candidates[p]
		raw, _ := json.Marshal(r.Target)
		if !optionsFull && len(out) < linuxmountwatch.MaxOptions && optionBytes+len(raw) <= 48<<10 {
			out = append(out, r.Target)
			optionBytes += len(raw)
		} else {
			optionsFull = true
		}
		if target != nil && r.Target == *target {
			selected = &r
		}
	}
	return out, len(keys) > len(out), selected, nil
}
