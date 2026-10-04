package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
)

func validJournalRecord(snap enrollmentstate.Snapshot, r journalrequest.Record) bool {
	d := r.Description
	last := journalrequest.LastEvent(r)
	return journalrequest.Validate(r) == nil && d.DeviceID == snap.Approval.DeviceID && d.CreatedAt.Unix() >= snap.Activation.At && last.Unix() < snap.Intent.NotAfter && (snap.Termination.At == 0 || last.Unix() <= snap.Termination.At)
}

// Every operation checks current profile, platform, activation, leaf, expiry,
// revocation and existing system-authority metadata within the same transaction.
// No query operation creates a synthetic system-inventory receipt.
func (s *Store) journalAuthority(t *transaction, id, hash string, now time.Time) (enrollmentstate.Snapshot, systemRecord, error) {
	snap, err := s.systemAuthority(t, id, hash, now)
	if err != nil {
		return enrollmentstate.Snapshot{}, systemRecord{}, err
	}
	r, ok := t.system[id]
	if !ok {
		return enrollmentstate.Snapshot{}, systemRecord{}, journalrequest.ErrNotReady
	}
	if r.JournalRequest != nil && r.JournalRequest.State != journalrequest.Expired && now.Before(journalrequest.LastEvent(*r.JournalRequest)) {
		return enrollmentstate.Snapshot{}, systemRecord{}, journalrequest.ErrInvalid
	}
	return snap, r, nil
}
func (s *Store) journalOperatorAuthority(t *transaction, device string, now time.Time) (enrollmentstate.Snapshot, systemRecord, error) {
	snap, err := systemDevice(t, device)
	if err != nil {
		return enrollmentstate.Snapshot{}, systemRecord{}, err
	}
	return s.journalAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now)
}
func currentJournal(r systemRecord, snap enrollmentstate.Snapshot, identity *journalrequest.Identity) (journalrequest.Record, error) {
	if r.JournalRequest == nil {
		return journalrequest.Record{}, journalrequest.ErrNotFound
	}
	query := *r.JournalRequest
	if query.Description.CertificateHash != snap.Issuance.CertificateHash || query.Description.DeviceID != snap.Approval.DeviceID {
		return journalrequest.Record{}, enrollmentstate.ErrProof
	}
	if identity != nil && query.Description.Identity != *identity {
		return journalrequest.Record{}, journalrequest.ErrConflict
	}
	return query, nil
}
func (s *Store) saveJournalRecord(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, system systemRecord, query journalrequest.Record) error {
	if !validJournalRecord(snap, query) {
		return journalrequest.ErrInvalid
	}
	system.JournalRequest = &query
	b, err := json.Marshal(system)
	if err != nil {
		return ErrStorage
	}
	if len(b) > systemMetadataLimit {
		return ErrSystemCapacity
	}
	if !validSystemRecord(snap, system) {
		return ErrStorage
	}
	result, err := t.conn.ExecContext(ctx, `UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, b, snap.InvitationID)
	if err != nil {
		return ErrStorage
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrStorage
	}
	t.system[snap.InvitationID] = system
	return s.checkSystemAdmission(ctx, t, snap.InvitationID)
}

// journalExpired latches a safely observed terminal expiry. It never refreshes
// creation, claim, result, or original expiry times and never resets the floor.
// Callers return ErrExpired only after this write; journalTransaction commits
// that safe terminal transition before returning the fixed public outcome.
func (s *Store) journalExpired(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, system systemRecord, query journalrequest.Record, now time.Time) (bool, error) {
	if query.State == journalrequest.Expired {
		return true, nil
	}
	if now.Before(query.Description.ExpiresAt) {
		return false, nil
	}
	query.State, query.ExpiredAt = journalrequest.Expired, &now
	if err := s.saveJournalRecord(ctx, t, snap, system, query); err != nil {
		return false, err
	}
	return true, nil
}

// journalTransaction uses the same bounded admission path as system reports.
// A journal expiry outcome commits its preceding terminal metadata write.
// Storage, validation, cancellation and commit errors take precedence; an
// uncommitted expiry is never reported as a successful terminal observation.
func (s *Store) journalTransaction(ctx context.Context, now time.Time, action func(*transaction) error) error {
	if !validStoreTime(now) {
		return enrollmentstate.ErrInvalid
	}
	release, err := s.inventoryAdmission(ctx)
	if err != nil {
		return err
	}
	defer release()
	var outcome error
	err = s.transact(ctx, func(t *transaction) error {
		err := action(t)
		if errors.Is(err, journalrequest.ErrExpired) {
			outcome = journalrequest.ErrExpired
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	return outcome
}

// CreateJournalRequest is a privileged operator call for an explicit new query.
// expectedFloor is a compare-and-swap guard (zero only when no query exists).
// Live pending/claimed work must be canceled or expire before replacement.
// Each successful call advances the per-device floor; it is not a retry API.
// No request is issued automatically when content or a claim response is lost.
func (s *Store) CreateJournalRequest(ctx context.Context, device string, expectedFloor uint64, q journalview.Query, now time.Time) (journalrequest.Description, error) {
	var out journalrequest.Description
	now = now.UTC()
	err := s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalOperatorAuthority(t, device, now)
		if err != nil {
			return err
		}
		floor := uint64(0)
		if previous := system.JournalRequest; previous != nil {
			// A terminal expiry is irreversible, but a new request still requires a
			// nondecreasing trusted authority clock.
			if now.Before(journalrequest.LastEvent(*previous)) {
				return journalrequest.ErrInvalid
			}
			floor = previous.Description.Identity.Sequence
		}
		if expectedFloor != floor {
			return journalrequest.ErrConflict
		}
		if previous := system.JournalRequest; previous != nil && now.Before(previous.Description.ExpiresAt) && (previous.State == journalrequest.Pending || previous.State == journalrequest.Claimed) {
			return journalrequest.ErrConflict
		}
		if floor == math.MaxUint64 {
			return ErrSystemCapacity
		}
		sequence := floor + 1
		query, err := journalrequest.New(device, snap.Issuance.CertificateHash, sequence, q, now)
		if err != nil {
			return err
		}
		if err = s.saveJournalRecord(ctx, t, snap, system, query); err != nil {
			return err
		}
		out = query.Description
		return nil
	})
	if err != nil {
		return journalrequest.Description{}, err
	}
	return out, nil
}

// PeekJournalRequest returns an unclaimed description only. The endpoint must
// validate local opt-in policy, then claim the exact identity and policy digest.
func (s *Store) PeekJournalRequest(ctx context.Context, id, hash string, now time.Time) (journalrequest.Description, error) {
	var out journalrequest.Description
	now = now.UTC()
	err := s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalAuthority(t, id, hash, now)
		if err != nil {
			return err
		}
		query, err := currentJournal(system, snap, nil)
		if err != nil {
			return err
		}
		expired, err := s.journalExpired(ctx, t, snap, system, query, now)
		if err != nil {
			return err
		}
		if expired {
			return journalrequest.ErrExpired
		}
		if err = journalrequest.CheckTime(query, now); err != nil {
			return err
		}
		if query.State != journalrequest.Pending {
			return journalrequest.ErrConsumed
		}
		out = query.Description
		return nil
	})
	if err != nil {
		return journalrequest.Description{}, err
	}
	return out, nil
}

// ClaimJournalRequest commits consumption before returning a one-shot grant.
// Duplicate/competing claims, including exact retries after uncertain delivery,
// never return a grant. Client-side durable consumption is additionally required.
func (s *Store) ClaimJournalRequest(ctx context.Context, id, hash string, claim journalrequest.Claim, now time.Time) (journalrequest.Grant, error) {
	var out journalrequest.Grant
	now = now.UTC()
	err := s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalAuthority(t, id, hash, now)
		if err != nil {
			return err
		}
		query, err := currentJournal(system, snap, &claim.Identity)
		if err != nil {
			return err
		}
		expired, err := s.journalExpired(ctx, t, snap, system, query, now)
		if err != nil {
			return err
		}
		if expired {
			return journalrequest.ErrExpired
		}
		if err = journalrequest.CheckTime(query, now); err != nil {
			return err
		}
		if !journalrequest.ValidDigest(claim.PolicyDigest) {
			return journalrequest.ErrInvalid
		}
		if query.State != journalrequest.Pending {
			return journalrequest.ErrConsumed
		}
		query.State, query.PolicyDigest, query.ClaimedAt = journalrequest.Claimed, claim.PolicyDigest, &now
		if err = s.saveJournalRecord(ctx, t, snap, system, query); err != nil {
			return err
		}
		out = journalrequest.Grant{Description: query.Description, PolicyDigest: claim.PolicyDigest, ClaimedAt: now}
		return nil
	})
	if err != nil {
		return journalrequest.Grant{}, err
	}
	return out, nil
}

// AcceptJournalResult receives only the digest of an already validated snapshot.
// It does not ingest log content. Exact retries preserve the first receipt and
// original request expiry. Any conflicting replacement fails closed.
func (s *Store) AcceptJournalResult(ctx context.Context, id, hash string, result journalrequest.Result, now time.Time) (journalrequest.Receipt, error) {
	var out journalrequest.Receipt
	now = now.UTC()
	err := s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalAuthority(t, id, hash, now)
		if err != nil {
			return err
		}
		query, err := currentJournal(system, snap, &result.Claim.Identity)
		if err != nil {
			return err
		}
		expired, err := s.journalExpired(ctx, t, snap, system, query, now)
		if err != nil {
			return err
		}
		if expired {
			return journalrequest.ErrExpired
		}
		if err = journalrequest.CheckTime(query, now); err != nil {
			return err
		}
		if !journalrequest.ValidDigest(result.ResultDigest) || !journalrequest.ValidDigest(result.Claim.PolicyDigest) {
			return journalrequest.ErrInvalid
		}
		if query.State != journalrequest.Claimed && query.State != journalrequest.Accepted || result.Claim.PolicyDigest != query.PolicyDigest {
			return journalrequest.ErrConflict
		}
		if query.Receipt != nil {
			if query.Receipt.ResultDigest != result.ResultDigest {
				return journalrequest.ErrConflict
			}
			out = *query.Receipt
			return nil
		}
		out = journalrequest.Receipt{Identity: query.Description.Identity, PolicyDigest: query.PolicyDigest, ResultDigest: result.ResultDigest, AcceptedAt: now, ExpiresAt: query.Description.ExpiresAt}
		query.State, query.Receipt = journalrequest.Accepted, &out
		return s.saveJournalRecord(ctx, t, snap, system, query)
	})
	if err != nil {
		return journalrequest.Receipt{}, err
	}
	return out, nil
}

// CancelJournalRequest suppresses a matching request without resetting its floor.
func (s *Store) CancelJournalRequest(ctx context.Context, device string, identity journalrequest.Identity, now time.Time) error {
	now = now.UTC()
	return s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalOperatorAuthority(t, device, now)
		if err != nil {
			return err
		}
		query, err := currentJournal(system, snap, &identity)
		if err != nil {
			return err
		}
		if query.State == journalrequest.Canceled && now.Before(query.Description.ExpiresAt) {
			return nil
		}
		expired, err := s.journalExpired(ctx, t, snap, system, query, now)
		if err != nil {
			return err
		}
		if expired {
			return journalrequest.ErrExpired
		}
		if err = journalrequest.CheckTime(query, now); err != nil {
			return err
		}
		query.State, query.CanceledAt = journalrequest.Canceled, &now
		return s.saveJournalRecord(ctx, t, snap, system, query)
	})
}

// JournalRequestStatus is privileged lifecycle metadata, never collection or
// content access permission. Canceled/expired requests suppress the result
// receipt. Revoke, credential expiry and leaf changes suppress all output.
func (s *Store) JournalRequestStatus(ctx context.Context, device string, now time.Time) (journalrequest.Status, error) {
	var out journalrequest.Status
	now = now.UTC()
	err := s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalOperatorAuthority(t, device, now)
		if err != nil {
			return err
		}
		query, err := currentJournal(system, snap, nil)
		if err != nil {
			return err
		}
		expired, err := s.journalExpired(ctx, t, snap, system, query, now)
		if err != nil {
			return err
		}
		state := query.State
		if expired {
			state = journalrequest.Expired
		}
		out = journalrequest.Status{Description: query.Description, State: state, ContentStatus: "unavailable"}
		if state == journalrequest.Accepted {
			out.Receipt = query.Receipt
		}
		return nil
	})
	if err != nil {
		return journalrequest.Status{}, err
	}
	return out, nil
}
