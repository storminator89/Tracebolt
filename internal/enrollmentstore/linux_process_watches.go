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
	"localrmm/internal/linuxprocesswatch"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"strconv"
	"time"
)

// WithLinuxProcessWatch reads only already accepted complete process chunks.
// It holds the existing source authority transaction through the bounded local
// operator-store callback. No collection, credential, scope or frame is changed.
func (s *Store) WithLinuxProcessWatch(ctx context.Context, device string, names []string, epoch string, clock func() time.Time, fn func(linuxprocesswatch.Input, func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || !completeProfile(s.config.Binding.CollectionProfile) || !enrollmentcrypto.ValidID(device, "agent_") || len(epoch) != 32 || len(names) > linuxprocesswatch.MaxRules {
		return enrollmentstate.ErrInvalid
	}
	ep, e := hex.DecodeString(epoch)
	if e != nil || hex.EncodeToString(ep) != epoch {
		return enrollmentstate.ErrInvalid
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !linuxprocesswatch.ValidName(name) || seen[name] {
			return enrollmentstate.ErrInvalid
		}
		seen[name] = true
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
		snap, e := s.overviewOperatorAuthority(t, device, "processes", started)
		if e != nil {
			return e
		}
		originalLeaf := t.currentCertificateHash(snap)
		raw, _ := json.Marshal(struct {
			Binding                         enrollmentstate.Binding
			Invitation, Device, Certificate string
		}{snap.Binding, snap.InvitationID, device, snap.Issuance.CertificateHash})
		digest := sha256.Sum256(append([]byte("tracebolt.linux-process-watch.identity.v1\x00"), raw...))
		clear(raw)
		identity := hex.EncodeToString(digest[:])
		mac := hmac.New(sha256.New, ep)
		_, _ = mac.Write(digest[:])
		token := "processsource_" + hex.EncodeToString(mac.Sum(nil)[:16])
		in := linuxprocesswatch.Input{DeviceID: device, Identity: identity, Epoch: epoch, SourceToken: token, Authorized: true, AuthorityUntil: time.Unix(t.currentCredentialNotAfter(snap), 0).UTC(), Reason: "unavailable", Counts: []linuxprocesswatch.Count{}}
		sample, reason, e := processWatchGeneration(ctx, t, snap, started)
		if e != nil {
			return e
		}
		in.Reason = reason
		if sample != nil {
			counts, unidentified, e := processWatchCounts(ctx, t, device, *sample, names)
			if e != nil {
				return e
			}
			sample.Generation.UnidentifiedRows = unidentified
			in.Sample = &sample.Generation
			in.Counts = counts
			in.Available = true
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
			current, e := s.overviewOperatorAuthority(t, device, "processes", at)
			if e != nil {
				return e
			}
			if current.InvitationID != snap.InvitationID || current.Issuance.CertificateHash != snap.Issuance.CertificateHash || current.Binding != snap.Binding || t.currentCertificateHash(current) != originalLeaf || t.currentCredentialNotAfter(current) != in.AuthorityUntil.Unix() {
				return enrollmentstate.ErrProof
			}
			latest, currentReason, e := processWatchGeneration(ctx, t, current, at)
			if e != nil {
				return e
			}
			if (latest == nil) != (sample == nil) || currentReason != reason {
				return enrollmentstate.ErrProof
			}
			if latest != nil && (latest.Binding != sample.Binding || latest.Generation.Sequence != sample.Generation.Sequence || !latest.Generation.CaptureStartedAt.Equal(sample.Generation.CaptureStartedAt) || !latest.Generation.ReceivedAt.Equal(sample.Generation.ReceivedAt)) {
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

type processWatchSample struct {
	Generation linuxprocesswatch.Generation
	Binding    OverviewBinding
	Manifest   overviewgeneration.Manifest
}

func processWatchGeneration(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, now time.Time) (*processWatchSample, string, error) {
	status, e := overviewStatus(ctx, t, snap, "processes", now)
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
	complete := status.Complete
	b := status.CompleteBinding
	m := complete.Manifest
	if status.Sequence != b.Sequence || status.Failure != nil || status.Transfer != nil && (status.Transfer.Manifest.GenerationID != b.GenerationID || status.Transfer.State != "complete") {
		return nil, "newer_attempt", nil
	}
	if complete.State != "complete" || m.CaptureStartedAt.After(now) || complete.CompletedAt.After(now) || !now.Before(m.CaptureStartedAt.Add(linuxprocesswatch.MaxAge)) || !now.Before(complete.CompletedAt.Add(linuxprocesswatch.MaxAge)) {
		return nil, "stale", nil
	}
	if m.Section != "processes" || m.Processes.Coverage != completeoverview.Complete || !m.Processes.CountExact || m.ObservedCount > completeoverview.MaxProcessRows || complete.AcceptedRows != m.ObservedCount || complete.AcceptedChunks != m.ChunkCount {
		return nil, "", ErrStorage
	}
	return &processWatchSample{linuxprocesswatch.Generation{Sequence: strconv.FormatUint(b.Sequence, 10), GenerationID: b.GenerationID, ManifestHash: b.ManifestHash, CaptureStartedAt: m.CaptureStartedAt, CaptureFinishedAt: m.CaptureFinishedAt, ReceivedAt: complete.CompletedAt, TotalRows: uint32(m.ObservedCount)}, b, m}, "none", nil
}

// Stream immutable original chunks through the existing selected-section proof.
// No search page, SQL prefix or unavailable name is treated as a zero result.
func processWatchCounts(ctx context.Context, t *transaction, device string, sample processWatchSample, names []string) ([]linuxprocesswatch.Count, uint32, error) {
	v, e := overviewgeneration.NewValidator(ctx, sample.Manifest)
	if e != nil {
		return nil, 0, ErrStorage
	}
	out := make([]linuxprocesswatch.Count, len(names))
	indices := map[string]int{}
	for i, n := range names {
		out[i].Name = n
		indices[n] = i
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT ordinal,body FROM co_chunks WHERE device=? AND generation=? ORDER BY ordinal LIMIT 1025`, overviewDevice(device, "processes"), sample.Binding.GenerationID)
	if e != nil {
		return nil, 0, ErrStorage
	}
	defer rows.Close()
	var count uint32
	var unknown uint32
	for rows.Next() {
		var ordinal uint32
		var raw []byte
		if rows.Scan(&ordinal, &raw) != nil || ordinal != count || count >= sample.Manifest.ChunkCount || len(raw) == 0 || len(raw) > overviewgeneration.MaxChunkBytes {
			return nil, 0, ErrStorage
		}
		var chunk overviewgeneration.Chunk
		if json.Unmarshal(raw, &chunk) != nil || overviewgeneration.ValidateChunk(chunk) != nil {
			return nil, 0, ErrStorage
		}
		canonical, _ := json.Marshal(chunk)
		if !bytes.Equal(canonical, raw) || v.Add(chunk) != nil {
			return nil, 0, ErrStorage
		}
		for _, row := range chunk.Items {
			if e = ctx.Err(); e != nil {
				return nil, 0, e
			}
			p := row.Process
			if p == nil {
				return nil, 0, ErrStorage
			}
			if p.Observation.Status != completeoverview.Observed || p.Name == nil || p.State == nil {
				unknown++
				continue
			}
			i, selected := indices[*p.Name]
			if !selected {
				continue
			}
			switch *p.State {
			case "running", "sleeping", "disk_sleep", "idle", "parked":
				out[i].ActiveCount++
			case "stopped", "tracing_stop", "zombie", "dead":
				out[i].NonRunningCount++
			default:
				return nil, 0, ErrStorage
			}
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil || count != sample.Manifest.ChunkCount {
		return nil, 0, ErrStorage
	}
	proof, e := v.Finish()
	if e != nil || !proof.Valid() || proof.ManifestSHA256() != sample.Binding.ManifestHash || unknown > uint32(sample.Manifest.ObservedCount) {
		return nil, 0, ErrStorage
	}
	return out, unknown, nil
}
