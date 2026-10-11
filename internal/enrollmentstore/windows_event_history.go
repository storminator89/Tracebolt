package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
)

var ErrWindowsHistoryUnavailable = errors.New("windows_history_unavailable")
var ErrWindowsHistoryCapacity = errors.New("windows_history_capacity")

type WindowsHistoryHeaders struct {
	GenerationID   string    `json:"generationId"`
	SnapshotDigest string    `json:"snapshotDigest"`
	CollectedAt    time.Time `json:"collectedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}
type WindowsHistoryStatus struct {
	DeviceID       string                         `json:"deviceId"`
	ExpectedFloor  string                         `json:"expectedFloor"`
	LocalStatus    string                         `json:"localStatus"`
	EndpointStatus string                         `json:"endpointStatus,omitempty"`
	Capability     *windowshistorywire.Capability `json:"-"`
	Headers        *WindowsHistoryHeaders         `json:"headers,omitempty"`
	Request        *windowshistoryrequest.Record  `json:"request,omitempty"`
	ObservedAt     time.Time                      `json:"-"`
	AuthorityUntil time.Time                      `json:"-"`
}
type windowsHistoryAuthority struct {
	device, certificate       string
	floor, capSequence        uint64
	capDigest                 string
	capability                *windowshistorywire.Capability
	request                   *windowshistoryrequest.Record
	resultDigest, localStatus string
}

func windowsHistoryTime(v string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, v)
	if e != nil || !validStoreTime(t) || t.Format(time.RFC3339Nano) != v {
		return time.Time{}, ErrStorage
	}
	return t, nil
}
func windowsHistorySequence(v string) (uint64, error) {
	n, e := strconv.ParseUint(v, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != v {
		return 0, ErrStorage
	}
	return n, nil
}
func windowsHistoryDigest(b []byte) string {
	v := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(v[:])
}
func (s *Store) windowsHistoryTransaction(ctx context.Context, now time.Time, fn func(*transaction, time.Time) error) error {
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) {
		return enrollmentstate.ErrInvalid
	}
	if s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return enrollmentstate.ErrProof
	}
	var outcome error
	e := s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = windowsHistoryNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		present, e := windowsHistorySchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if !present {
			return ErrWindowsHistoryUnavailable
		}
		var last string
		if t.conn.QueryRowContext(ctx, `SELECT last_time FROM enrollment_windows_history_meta WHERE id=1`).Scan(&last) != nil {
			return ErrStorage
		}
		if last != "" {
			at, e := windowsHistoryTime(last)
			if e != nil {
				return e
			}
			if now.Before(at) {
				return enrollmentstate.ErrInvalid
			}
		}
		e = fn(t, now)
		// Authority failures and terminal observations may first persist cancellation.
		if e != nil && !errors.Is(e, ErrWindowsHistoryUnavailable) && !errors.Is(e, windowshistoryrequest.ErrExpired) && !errors.Is(e, windowshistoryrequest.ErrCanceled) && !errors.Is(e, windowshistoryrequest.ErrDisabled) {
			return e
		}
		outcome = e
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_windows_history_meta SET last_time=? WHERE id=1`, now.Format(time.RFC3339Nano)); e != nil {
			return ErrStorage
		}
		return nil
	})
	if e != nil {
		return e
	}
	return outcome
}
func loadWindowsHistoryAuthority(ctx context.Context, t *transaction, device string) (windowsHistoryAuthority, error) {
	a := windowsHistoryAuthority{device: device, localStatus: "unavailable"}
	var floor, seq string
	var requestPresent int
	var raw []byte
	e := t.conn.QueryRowContext(ctx, `SELECT certificate,floor,capability_sequence,capability_digest,capability,request_present FROM enrollment_windows_history_authority WHERE device=?`, device).Scan(&a.certificate, &floor, &seq, &a.capDigest, &raw, &requestPresent)
	if e == sql.ErrNoRows {
		return a, nil
	}
	if e != nil {
		return a, ErrStorage
	}
	a.floor, e = windowsHistorySequence(floor)
	if e != nil {
		return a, e
	}
	a.capSequence, e = windowsHistorySequence(seq)
	if e != nil {
		return a, e
	}
	if len(raw) > 0 {
		c, e := windowshistorywire.DecodeCapability(raw)
		if e != nil || c.DeviceID != device || c.CertificateHash != a.certificate || c.Sequence != a.capSequence || windowsHistoryDigest(raw) != a.capDigest {
			return a, ErrStorage
		}
		a.capability = &c
	}
	e = t.conn.QueryRowContext(ctx, `SELECT body,result_digest,local_status FROM enrollment_windows_history_requests WHERE device=?`, device).Scan(&raw, &a.resultDigest, &a.localStatus)
	if e == sql.ErrNoRows {
		if requestPresent != 0 {
			return a, ErrStorage
		}
		return a, nil
	}
	if requestPresent != 1 {
		return a, ErrStorage
	}
	if e != nil {
		return a, ErrStorage
	}
	r, e := windowshistoryrequest.Decode(raw)
	if e != nil || r.Description.DeviceID != device || r.Description.Identity.Sequence != a.floor {
		return a, ErrStorage
	}
	a.request = &r
	if (r.Receipt != nil) != (a.resultDigest != "") {
		return a, ErrStorage
	}
	return a, nil
}
func saveWindowsHistoryAuthority(ctx context.Context, t *transaction, a windowsHistoryAuthority) error {
	var raw []byte
	var e error
	if a.capability != nil {
		raw, e = windowshistorywire.EncodeCapability(*a.capability)
		if e != nil {
			return ErrStorage
		}
	} else {
		raw = []byte{}
	}
	if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_history_authority(device,certificate,floor,capability_sequence,capability_digest,capability,request_present) VALUES(?,?,?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET certificate=excluded.certificate,floor=excluded.floor,capability_sequence=excluded.capability_sequence,capability_digest=excluded.capability_digest,capability=excluded.capability,request_present=excluded.request_present`, a.device, a.certificate, strconv.FormatUint(a.floor, 10), strconv.FormatUint(a.capSequence, 10), a.capDigest, raw, a.request != nil); e != nil {
		return ErrStorage
	}
	var count int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_history_authority`).Scan(&count) != nil || count > 25 {
		return ErrWindowsHistoryCapacity
	}
	if a.request != nil {
		raw, e = windowshistoryrequest.Encode(*a.request)
		if e != nil {
			return ErrStorage
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_history_requests(device,body,result_digest,local_status) VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body,result_digest=excluded.result_digest,local_status=excluded.local_status`, a.device, raw, a.resultDigest, a.localStatus); e != nil {
			return ErrStorage
		}
	}
	return nil
}
func cancelWindowsHistory(a *windowsHistoryAuthority, now time.Time) error {
	if a.request == nil || a.request.State == windowshistoryrequest.Canceled || a.request.State == windowshistoryrequest.Expired {
		return nil
	}
	var r windowshistoryrequest.Record
	var e error
	if !now.Before(a.request.Description.ExpiresAt) {
		r, e = windowshistoryrequest.Expire(*a.request, now)
	} else {
		r, e = windowshistoryrequest.Cancel(*a.request, a.request.Description.Identity, now)
	}
	if e != nil {
		return e
	}
	a.request = &r
	return nil
}
func (s *Store) windowsHistoryIdentity(t *transaction, device, certificate string, now time.Time) (enrollmentstate.Snapshot, error) {
	for _, v := range t.engine.Snapshots() {
		if v.Approval.DeviceID != device {
			continue
		}
		if v.Platform != "windows" || v.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
			return v, ErrWindowsHistoryUnavailable
		}
		if certificate == "" {
			certificate = t.currentCertificateHash(v)
		}
		if err := t.authorizeCurrentCredential(v, certificate, now); err != nil {
			if errors.Is(err, ErrStorage) || errors.Is(err, enrollmentstate.ErrProof) || errors.Is(err, enrollmentstate.ErrInvalid) {
				return v, err
			}
			return v, ErrWindowsHistoryUnavailable
		}
		// The final live transaction guard preserves immutable scope bindings,
		// while only the currently authenticated leaf authorizes this operation.
		snapshot, leaf, sampled := v, certificate, now
		t.beforeCommit = append(t.beforeCommit, func() error {
			// Earlier guards in a maintenance batch may already have advanced
			// this transaction's durable floor. Never clamp or lower it.
			var last string
			if t.conn.QueryRowContext(t.ctx, `SELECT last_time FROM enrollment_windows_history_meta WHERE id=1`).Scan(&last) != nil {
				return ErrStorage
			}
			floor := sampled
			if last != "" {
				prior, err := windowsHistoryTime(last)
				if err != nil {
					return err
				}
				if prior.After(floor) {
					floor = prior
				}
			}
			fresh, err := windowsHistoryNow(t.ctx, floor)
			if err != nil {
				return err
			}
			if err = t.authorizeCurrentCredential(snapshot, leaf, fresh); err != nil {
				return err
			}
			if err = windowsHistorySessionAt(t.ctx, fresh); err != nil {
				return err
			}
			a, err := loadWindowsHistoryAuthority(t.ctx, t, snapshot.Approval.DeviceID)
			if err != nil {
				return err
			}
			if a.request != nil && (a.request.State == windowshistoryrequest.Pending || a.request.State == windowshistoryrequest.Claimed || a.request.State == windowshistoryrequest.Accepted) {
				if !fresh.Before(a.request.Description.ExpiresAt) {
					return windowshistoryrequest.ErrExpired
				}
				if a.capability != nil && windowshistorywire.CapabilityFresh(*a.capability, sampled) == nil && windowshistorywire.CapabilityFresh(*a.capability, fresh) != nil {
					return ErrWindowsHistoryUnavailable
				}
			}
			if _, err = t.conn.ExecContext(t.ctx, `UPDATE enrollment_windows_history_meta SET last_time=? WHERE id=1`, fresh.Format(time.RFC3339Nano)); err != nil {
				return ErrStorage
			}
			return nil
		})
		return v, nil
	}
	return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
}
func (s *Store) windowsHistoryCurrent(ctx context.Context, t *transaction, device, cert string, now time.Time) (enrollmentstate.Snapshot, windowsHistoryAuthority, error) {
	a, e := loadWindowsHistoryAuthority(ctx, t, device)
	if e != nil {
		return enrollmentstate.Snapshot{}, a, e
	}
	snap, e := s.windowsHistoryIdentity(t, device, cert, now)
	if e != nil {
		// A retired or mismatched transport leaf has no authority to cancel a
		// still-live anchor-bound request. Only identity expiry/revocation below
		// may persist the existing terminal cleanup.
		if errors.Is(e, enrollmentstate.ErrProof) || errors.Is(e, enrollmentstate.ErrInvalid) || errors.Is(e, ErrStorage) {
			return snap, a, e
		}
		if a.certificate != "" {
			if ce := cancelWindowsHistory(&a, now); ce != nil {
				return snap, a, ce
			}
			if ce := saveWindowsHistoryAuthority(ctx, t, a); ce != nil {
				return snap, a, ce
			}
		}
		return snap, a, e
	}
	if a.certificate != "" && a.certificate != snap.Issuance.CertificateHash {
		if e = cancelWindowsHistory(&a, now); e != nil {
			return snap, a, e
		}
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return snap, a, e
		}
		return snap, a, ErrWindowsHistoryUnavailable
	}
	if a.request != nil && !now.Before(a.request.Description.ExpiresAt) && a.request.State != windowshistoryrequest.Expired {
		r, e := windowshistoryrequest.Expire(*a.request, now)
		if e != nil {
			return snap, a, e
		}
		a.request = &r
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return snap, a, e
		}
	}
	if a.request != nil && !now.Before(a.request.Description.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge)) {
		if e = cancelWindowsHistory(&a, now); e != nil {
			return snap, a, e
		}
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return snap, a, e
		}
	}
	if e = purgeWindowsHistoryRequest(ctx, t, &a, now); e != nil {
		return snap, a, e
	}
	return snap, a, nil
}
func windowsHistoryLocal(a windowsHistoryAuthority, s enrollmentstate.Snapshot) windowshistoryrequest.LocalContext {
	return windowshistoryrequest.LocalContext{SenderBinding: a.capability.Consent.SenderBinding, Profile: s.Binding.Profile, DeviceID: s.Approval.DeviceID, CertificateHash: s.Issuance.CertificateHash}
}
func windowsHistoryReady(a windowsHistoryAuthority, now time.Time) error {
	if a.capability == nil || windowshistorywire.CapabilityFresh(*a.capability, now) != nil {
		return ErrWindowsHistoryUnavailable
	}
	if !a.capability.Consent.Enabled {
		return windowshistoryrequest.ErrDisabled
	}
	return nil
}
func (s *Store) ReportWindowsHistoryCapability(ctx context.Context, device, cert string, c windowshistorywire.Capability, now time.Time) (windowshistorywire.Capability, error) {
	var out windowshistorywire.Capability
	raw, e := windowshistorywire.EncodeCapability(c)
	if e != nil || device != c.DeviceID || windowshistorywire.CapabilityFresh(c, now) != nil {
		return out, windowshistoryrequest.ErrInvalid
	}
	e = s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		snap, e := s.windowsHistoryIdentity(t, device, cert, now)
		if e != nil {
			return e
		}
		if c.CertificateHash != snap.Issuance.CertificateHash {
			return windowshistoryrequest.ErrInvalid
		}
		if c.Consent.Profile != snap.Binding.Profile {
			return enrollmentstate.ErrProof
		}
		a, e := loadWindowsHistoryAuthority(ctx, t, device)
		if e != nil {
			return e
		}
		if c.Sequence < a.capSequence || c.Sequence == a.capSequence && windowsHistoryDigest(raw) != a.capDigest {
			return windowshistoryrequest.ErrConflict
		}
		if c.Sequence == a.capSequence {
			if a.capability == nil {
				return ErrWindowsHistoryUnavailable
			}
			out = *a.capability
			return nil
		}
		if a.capability != nil && c.CollectedAt.Before(a.capability.CollectedAt) {
			return windowshistoryrequest.ErrConflict
		}
		if a.capability != nil && (a.certificate != snap.Issuance.CertificateHash || c.PolicyDigest != a.capability.PolicyDigest) || !c.Consent.Enabled {
			if e = cancelWindowsHistory(&a, now); e != nil {
				return e
			}
		}
		credential := t.credentials[snap.InvitationID]
		credential.WindowsHistoryAuthorityInitialized = true
		t.credentials[snap.InvitationID] = credential
		a.certificate = snap.Issuance.CertificateHash
		a.capSequence = c.Sequence
		a.capDigest = windowsHistoryDigest(raw)
		a.capability = &c
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return e
		}
		out = c
		return nil
	})
	return out, e
}
func (s *Store) WindowsHistoryStatus(ctx context.Context, device string, now time.Time) (WindowsHistoryStatus, error) {
	out := WindowsHistoryStatus{DeviceID: device, ExpectedFloor: "0", LocalStatus: "unavailable", ObservedAt: now}
	e := s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		snap, a, e := s.windowsHistoryCurrent(ctx, t, device, "", now)
		if e != nil {
			return e
		}
		out.ExpectedFloor = strconv.FormatUint(a.floor, 10)
		out.Capability = a.capability
		out.Request = a.request
		if windowshistorywire.ValidLocalStatus(a.localStatus) {
			out.EndpointStatus = a.localStatus
		}
		out.AuthorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
		if a.capability != nil {
			out.LocalStatus = "enabled"
			if !a.capability.Consent.Enabled {
				out.LocalStatus = "disabled"
			} else if windowshistorywire.CapabilityFresh(*a.capability, now) != nil {
				out.LocalStatus = "stale"
			}
		}
		return e
	})
	return out, e
}

// CreateWindowsHistorySearch installs exactly one fresh immutable search operation.
func (s *Store) CreateWindowsHistorySearch(ctx context.Context, device string, floor uint64, search windowseventhistory.Search, now time.Time) (windowshistoryrequest.Description, error) {
	return s.createWindowsHistory(ctx, device, floor, nil, now, func(snap enrollmentstate.Snapshot, a windowsHistoryAuthority, sampled time.Time) (windowshistoryrequest.Record, error) {
		return windowshistoryrequest.NewSearch(device, snap.Issuance.CertificateHash, floor+1, a.capability.Consent.GrantID, search, sampled)
	})
}

// The cache supplies private accepted rows, but the transaction independently
// compares their digest against the original durable receipt before selection.
func (s *Store) CreateWindowsHistoryMessages(ctx context.Context, device string, floor uint64, receipt windowshistoryrequest.Receipt, report windowseventhistory.Report, selected []windowshistoryrequest.Selection, now time.Time) (windowshistoryrequest.Description, error) {
	return s.createWindowsHistory(ctx, device, floor, &receipt, now, func(snap enrollmentstate.Snapshot, a windowsHistoryAuthority, sampled time.Time) (windowshistoryrequest.Record, error) {
		if a.request == nil || a.request.Description.Query.Search == nil {
			return windowshistoryrequest.Record{}, windowshistoryrequest.ErrConflict
		}
		digest, err := windowshistorywire.ReportDigest(report, a.request.Description.Query)
		if err != nil || digest != receipt.ResultDigest {
			return windowshistoryrequest.Record{}, windowshistoryrequest.ErrConflict
		}
		return windowshistoryrequest.NewMessages(device, snap.Issuance.CertificateHash, floor+1, a.capability.Consent.GrantID, *a.request, report, selected, sampled)
	})
}
func (s *Store) createWindowsHistory(ctx context.Context, device string, floor uint64, previous *windowshistoryrequest.Receipt, now time.Time, build func(enrollmentstate.Snapshot, windowsHistoryAuthority, time.Time) (windowshistoryrequest.Record, error)) (windowshistoryrequest.Description, error) {
	var out windowshistoryrequest.Description
	err := s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		snap, a, err := s.windowsHistoryCurrent(ctx, t, device, "", now)
		if err != nil {
			return err
		}
		if err = windowsHistoryReady(a, now); err != nil {
			return err
		}
		if a.floor != floor || floor == math.MaxUint64 {
			return windowshistoryrequest.ErrConflict
		}
		if previous != nil {
			if a.request == nil || a.request.State != windowshistoryrequest.Accepted || a.request.Receipt == nil || *a.request.Receipt != *previous {
				return windowshistoryrequest.ErrConflict
			}
		} else if a.request != nil && (a.request.State == windowshistoryrequest.Pending || a.request.State == windowshistoryrequest.Claimed || a.request.State == windowshistoryrequest.Accepted) {
			return windowshistoryrequest.ErrConflict
		}
		record, err := build(snap, a, now)
		if err != nil {
			return err
		}
		a.floor = floor + 1
		a.request = &record
		a.resultDigest = ""
		a.localStatus = "pending"
		if err = saveWindowsHistoryAuthority(ctx, t, a); err != nil {
			return err
		}
		out = record.Description
		return nil
	})
	return out, err
}
func (s *Store) CancelWindowsHistoryRequest(ctx context.Context, device string, id windowshistoryrequest.Identity, now time.Time) error {
	return s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		_, a, e := s.windowsHistoryCurrent(ctx, t, device, "", now)
		if e != nil {
			return e
		}
		if a.request == nil || a.request.Description.Identity != id {
			return windowshistoryrequest.ErrConflict
		}
		if e = cancelWindowsHistory(&a, now); e != nil {
			return e
		}
		return saveWindowsHistoryAuthority(ctx, t, a)
	})
}
func (s *Store) PeekWindowsHistoryRequest(ctx context.Context, device, cert string, now time.Time) (*windowshistoryrequest.Description, error) {
	var out *windowshistoryrequest.Description
	e := s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		_, a, e := s.windowsHistoryCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if e = windowsHistoryReady(a, now); e != nil {
			return e
		}
		if a.request != nil && a.request.State == windowshistoryrequest.Pending {
			d := a.request.Description
			out = &d
		}
		return nil
	})
	return out, e
}
func (s *Store) ClaimWindowsHistoryRequest(ctx context.Context, device, cert string, claim windowshistorywire.Claim, now time.Time) (windowshistorywire.Grant, error) {
	var out windowshistorywire.Grant
	e := s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		snap, a, e := s.windowsHistoryCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if e = windowsHistoryReady(a, now); e != nil {
			return e
		}
		if a.request == nil {
			return ErrWindowsHistoryUnavailable
		}
		expected, e := windowshistorywire.ClaimFor(a.request.Description, a.capability.PolicyDigest)
		if e != nil || expected != claim {
			return windowshistoryrequest.ErrConflict
		}
		r, e := windowshistoryrequest.Claim(*a.request, claim.Identity, a.capability.Consent, windowsHistoryLocal(a, snap), now)
		if e != nil {
			return e
		}
		a.request = &r
		a.localStatus = "claimed"
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return e
		}
		out, e = windowshistorywire.GrantFor(r)
		return e
	})
	return out, e
}

// The boolean is true only for the first committed result. Exact retries return
// the original receipt without permission to republish lost content.
func (s *Store) AcceptWindowsHistoryResult(ctx context.Context, device, cert string, result windowshistorywire.Result, now time.Time) (windowshistoryrequest.Receipt, bool, error) {
	var out windowshistoryrequest.Receipt
	first := false
	e := s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		snap, a, e := s.windowsHistoryCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if e = windowsHistoryReady(a, now); e != nil {
			return e
		}
		if a.request == nil {
			return ErrWindowsHistoryUnavailable
		}
		if e = windowshistorywire.ValidateResult(result, a.request.Description); e != nil {
			return e
		}
		d, e := windowshistorywire.ResultDigest(result)
		if e != nil {
			return e
		}
		expected, e := windowshistorywire.ClaimFor(a.request.Description, a.capability.PolicyDigest)
		if e != nil || expected != result.Claim {
			return windowshistoryrequest.ErrConflict
		}
		if a.request.State == windowshistoryrequest.Accepted {
			if a.resultDigest != d {
				return windowshistoryrequest.ErrConflict
			}
			out = *a.request.Receipt
			return nil
		}
		r, e := windowshistoryrequest.Accept(*a.request, result.Claim.Identity, a.capability.Consent, windowsHistoryLocal(a, snap), result.Report, now)
		if e != nil {
			return e
		}
		a.request = &r
		a.resultDigest = d
		a.localStatus = "accepted"
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return e
		}
		out = *r.Receipt
		first = true
		return nil
	})
	if e != nil {
		return windowshistoryrequest.Receipt{}, false, e
	}
	return out, first, nil
}
func (s *Store) ReportWindowsHistoryStatus(ctx context.Context, device, cert string, in windowshistorywire.StatusInput, now time.Time) error {
	return s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		_, a, e := s.windowsHistoryCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if a.request == nil || a.capability == nil {
			return ErrWindowsHistoryUnavailable
		}
		claim, e := windowshistorywire.ClaimFor(a.request.Description, a.capability.PolicyDigest)
		if e != nil || claim != in.Claim {
			return windowshistoryrequest.ErrConflict
		}
		if e = windowshistoryrequest.CheckTime(*a.request, now); e != nil {
			return e
		}
		if !windowshistorywire.ValidLocalStatus(in.LocalStatus) {
			return windowshistoryrequest.ErrInvalid
		}
		a.localStatus = in.LocalStatus
		if in.LocalStatus == "disabled" || in.LocalStatus == "expired" || in.LocalStatus == "canceled" || in.LocalStatus == "denied" || in.LocalStatus == "reader_unavailable" || in.LocalStatus == "budget_exhausted" || in.LocalStatus == "result_lost" {
			if e = cancelWindowsHistory(&a, now); e != nil {
				return e
			}
		}
		return saveWindowsHistoryAuthority(ctx, t, a)
	})
}

// MaintainWindowsHistory is also used at startup, when every pending or
// claimed request has lost its non-durable session owner.
func (s *Store) MaintainWindowsHistory(ctx context.Context, now time.Time, abandon bool) error {
	return s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		_, err := s.maintainWindowsHistory(ctx, t, now, abandon, nil)
		return err
	})
}

// MaintainWindowsHistoryAuthorities validates the complete store only once, then
// expires/purges authority and cancels unowned work in that same transaction.
// The caller holds the cache ownership mutex while taking and applying this
// exact-identity snapshot. Returned metadata is not a disclosure authorization;
// the cache must recheck its trusted clock and live sessions after the commit.
func (s *Store) MaintainWindowsHistoryAuthorities(ctx context.Context, live map[string]windowshistoryrequest.Identity, now time.Time) (map[string]WindowsHistoryStatus, error) {
	if live == nil {
		live = map[string]windowshistoryrequest.Identity{}
	}
	if len(live) > 25 {
		return nil, ErrWindowsHistoryCapacity
	}
	var out map[string]WindowsHistoryStatus
	err := s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		var err error
		out, err = s.maintainWindowsHistory(ctx, t, now, false, live)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) maintainWindowsHistory(ctx context.Context, t *transaction, now time.Time, abandon bool, live map[string]windowshistoryrequest.Identity) (map[string]WindowsHistoryStatus, error) {
	rows, e := t.conn.QueryContext(ctx, `SELECT device FROM enrollment_windows_history_authority ORDER BY device`)
	if e != nil {
		return nil, ErrStorage
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return nil, ErrStorage
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(ids) > 25 {
		return nil, ErrStorage
	}
	out := make(map[string]WindowsHistoryStatus, len(ids))
	for _, id := range ids {
		a, e := loadWindowsHistoryAuthority(ctx, t, id)
		if e != nil {
			return nil, e
		}
		snap, authorityErr := s.windowsHistoryIdentity(t, id, "", now)
		if authorityErr != nil && !errors.Is(authorityErr, ErrWindowsHistoryUnavailable) && !errors.Is(authorityErr, enrollmentstate.ErrNotFound) {
			return nil, authorityErr
		}
		unowned := a.request != nil && (abandon || live != nil && live[id] != a.request.Description.Identity) && (a.request.State == windowshistoryrequest.Pending || a.request.State == windowshistoryrequest.Claimed)
		if unowned || authorityErr != nil || a.request != nil && !now.Before(a.request.Description.ExpiresAt) {
			if e = cancelWindowsHistory(&a, now); e != nil {
				return nil, e
			}
		}
		if e = purgeWindowsHistoryRequest(ctx, t, &a, now); e != nil {
			return nil, e
		}
		// Expired report payloads can be purged without erasing replay floors.
		if a.capability != nil && !now.Before(a.capability.CollectedAt.Add(24*time.Hour)) {
			a.capability = nil
		}
		if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
			return nil, e
		}
		status := WindowsHistoryStatus{DeviceID: id, ExpectedFloor: strconv.FormatUint(a.floor, 10), LocalStatus: "unavailable", Request: a.request, Capability: a.capability, ObservedAt: now}
		if authorityErr == nil {
			status.AuthorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
			if a.capability != nil {
				status.LocalStatus = "enabled"
				if !a.capability.Consent.Enabled {
					status.LocalStatus = "disabled"
				} else if windowshistorywire.CapabilityFresh(*a.capability, now) != nil {
					status.LocalStatus = "stale"
				}
			}
		}
		out[id] = status
	}
	return out, nil
}

// Original header retention also bounds durable selected-header metadata. The
// independent floor row remains after this metadata is gone.
func purgeWindowsHistoryRequest(ctx context.Context, t *transaction, a *windowsHistoryAuthority, now time.Time) error {
	if a.request == nil || now.Before(a.request.Description.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge)) {
		return nil
	}
	if _, e := t.conn.ExecContext(ctx, `DELETE FROM enrollment_windows_history_requests WHERE device=?`, a.device); e != nil {
		return ErrStorage
	}
	if _, e := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_history_authority SET request_present=0 WHERE device=?`, a.device); e != nil {
		return ErrStorage
	}
	a.request = nil
	a.resultDigest = ""
	a.localStatus = "unavailable"
	return nil
}

// Called while the cache holds its ownership mutex: create cannot install a
// new live owner between the snapshot and this durable cleanup transaction.
func (s *Store) CancelUnownedWindowsHistoryRequests(ctx context.Context, live map[string]windowshistoryrequest.Identity, now time.Time) error {
	return s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		rows, e := t.conn.QueryContext(ctx, `SELECT device FROM enrollment_windows_history_requests ORDER BY device`)
		if e != nil {
			return ErrStorage
		}
		var ids []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return ErrStorage
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return ErrStorage
		}
		for _, id := range ids {
			a, e := loadWindowsHistoryAuthority(ctx, t, id)
			if e != nil {
				return e
			}
			if a.request == nil || a.request.State != windowshistoryrequest.Pending && a.request.State != windowshistoryrequest.Claimed {
				continue
			}
			if expected, ok := live[id]; ok && expected == a.request.Description.Identity {
				continue
			}
			if e = cancelWindowsHistory(&a, now); e != nil {
				return e
			}
			if e = saveWindowsHistoryAuthority(ctx, t, a); e != nil {
				return e
			}
		}
		return nil
	})
}

// These values are installed by trusted manager/cache boundaries, never browser JSON.
type windowsHistoryClockKey struct{}

func WithWindowsHistoryClock(ctx context.Context, now func() time.Time) context.Context {
	return context.WithValue(ctx, windowsHistoryClockKey{}, now)
}
func windowsHistoryNow(ctx context.Context, floor time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(floor) {
		return time.Time{}, enrollmentstate.ErrInvalid
	}
	if clock, ok := ctx.Value(windowsHistoryClockKey{}).(func() time.Time); ok {
		if clock == nil {
			return time.Time{}, enrollmentstate.ErrInvalid
		}
		fresh := clock().UTC()
		if !validStoreTime(fresh) || fresh.Before(floor) {
			return time.Time{}, enrollmentstate.ErrInvalid
		}
		return fresh, nil
	}
	return floor, nil
}

type windowsHistorySessionKey struct{}
type windowsHistorySession struct {
	until  time.Time
	active func() bool
}

func WithWindowsHistorySession(ctx context.Context, until time.Time, active func() bool) context.Context {
	return context.WithValue(ctx, windowsHistorySessionKey{}, windowsHistorySession{until, active})
}
func windowsHistorySessionAt(ctx context.Context, now time.Time) error {
	if ctx == nil {
		return enrollmentstate.ErrInvalid
	}
	if s, ok := ctx.Value(windowsHistorySessionKey{}).(windowsHistorySession); ok && (s.active == nil || !s.active() || !now.Before(s.until)) {
		return enrollmentstate.ErrProof
	}
	return nil
}

// AuthorizeWindowsHistoryReply is read-only request disclosure authority; it
// independently resolves the live authenticated transport credential.
func (s *Store) AuthorizeWindowsHistoryReply(ctx context.Context, device, certificate string, id windowshistoryrequest.Identity, now time.Time) error {
	return s.windowsHistoryTransaction(ctx, now, func(t *transaction, now time.Time) error {
		_, a, err := s.windowsHistoryCurrent(ctx, t, device, certificate, now)
		if err != nil {
			return err
		}
		if err = windowsHistoryReady(a, now); err != nil {
			return err
		}
		if a.request == nil || a.request.Description.Identity != id || a.request.Description.GrantID != a.capability.Consent.GrantID || (a.request.State != windowshistoryrequest.Pending && a.request.State != windowshistoryrequest.Claimed) {
			return ErrWindowsHistoryUnavailable
		}
		return nil
	})
}
