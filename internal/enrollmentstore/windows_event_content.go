package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
)

var ErrWindowsEventUnavailable = errors.New("windows_event_content_unavailable")
var ErrWindowsEventCapacity = errors.New("windows_event_content_capacity")

type WindowsEventHeaders struct {
	GenerationID   string    `json:"generationId"`
	SnapshotDigest string    `json:"snapshotDigest"`
	CollectedAt    time.Time `json:"collectedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}
type WindowsEventStatus struct {
	DeviceID       string                       `json:"deviceId"`
	ExpectedFloor  string                       `json:"expectedFloor"`
	LocalStatus    string                       `json:"localStatus"`
	EndpointStatus string                       `json:"endpointStatus,omitempty"`
	Capability     *windowseventwire.Capability `json:"-"`
	Headers        *WindowsEventHeaders         `json:"headers,omitempty"`
	Request        *windowseventrequest.Record  `json:"request,omitempty"`
	ObservedAt     time.Time                    `json:"-"`
	AuthorityUntil time.Time                    `json:"-"`
}
type windowsEventAuthority struct {
	device, certificate       string
	floor, capSequence        uint64
	capDigest                 string
	capability                *windowseventwire.Capability
	request                   *windowseventrequest.Record
	resultDigest, localStatus string
}

func windowsEventTime(v string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, v)
	if e != nil || !validStoreTime(t) || t.Format(time.RFC3339Nano) != v {
		return time.Time{}, ErrStorage
	}
	return t, nil
}
func windowsEventSequence(v string) (uint64, error) {
	n, e := strconv.ParseUint(v, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != v {
		return 0, ErrStorage
	}
	return n, nil
}
func windowsEventDigest(b []byte) string {
	v := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(v[:])
}
func (s *Store) windowsEventTransaction(ctx context.Context, now time.Time, fn func(*transaction) error) error {
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) {
		return enrollmentstate.ErrInvalid
	}
	if s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return enrollmentstate.ErrProof
	}
	var outcome error
	e := s.transact(ctx, func(t *transaction) error {
		present, e := windowsEventSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if !present {
			return ErrWindowsEventUnavailable
		}
		var last string
		if t.conn.QueryRowContext(ctx, `SELECT last_time FROM enrollment_windows_event_meta WHERE id=1`).Scan(&last) != nil {
			return ErrStorage
		}
		if last != "" {
			at, e := windowsEventTime(last)
			if e != nil {
				return e
			}
			if now.Before(at) {
				return enrollmentstate.ErrInvalid
			}
		}
		e = fn(t)
		// Authority failures and terminal observations may first persist cancellation.
		if e != nil && !errors.Is(e, ErrWindowsEventUnavailable) && !errors.Is(e, windowseventrequest.ErrExpired) && !errors.Is(e, windowseventrequest.ErrCanceled) && !errors.Is(e, windowseventrequest.ErrDisabled) {
			return e
		}
		outcome = e
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_windows_event_meta SET last_time=? WHERE id=1`, now.Format(time.RFC3339Nano)); e != nil {
			return ErrStorage
		}
		return nil
	})
	if e != nil {
		return e
	}
	return outcome
}
func loadWindowsEventAuthority(ctx context.Context, t *transaction, device string) (windowsEventAuthority, error) {
	a := windowsEventAuthority{device: device, localStatus: "unavailable"}
	var floor, seq string
	var requestPresent int
	var raw []byte
	e := t.conn.QueryRowContext(ctx, `SELECT certificate,floor,capability_sequence,capability_digest,capability,request_present FROM enrollment_windows_event_authority WHERE device=?`, device).Scan(&a.certificate, &floor, &seq, &a.capDigest, &raw, &requestPresent)
	if e == sql.ErrNoRows {
		return a, nil
	}
	if e != nil {
		return a, ErrStorage
	}
	a.floor, e = windowsEventSequence(floor)
	if e != nil {
		return a, e
	}
	a.capSequence, e = windowsEventSequence(seq)
	if e != nil {
		return a, e
	}
	if len(raw) > 0 {
		c, e := windowseventwire.DecodeCapability(raw)
		if e != nil || c.DeviceID != device || c.CertificateHash != a.certificate || c.Sequence != a.capSequence || windowsEventDigest(raw) != a.capDigest {
			return a, ErrStorage
		}
		a.capability = &c
	}
	e = t.conn.QueryRowContext(ctx, `SELECT body,result_digest,local_status FROM enrollment_windows_event_requests WHERE device=?`, device).Scan(&raw, &a.resultDigest, &a.localStatus)
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
	r, e := windowseventrequest.Decode(raw)
	if e != nil || r.Description.DeviceID != device || r.Description.Identity.Sequence != a.floor {
		return a, ErrStorage
	}
	a.request = &r
	if (r.Receipt != nil) != (a.resultDigest != "") {
		return a, ErrStorage
	}
	return a, nil
}
func saveWindowsEventAuthority(ctx context.Context, t *transaction, a windowsEventAuthority) error {
	var raw []byte
	var e error
	if a.capability != nil {
		raw, e = windowseventwire.EncodeCapability(*a.capability)
		if e != nil {
			return ErrStorage
		}
	} else {
		raw = []byte{}
	}
	if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_event_authority(device,certificate,floor,capability_sequence,capability_digest,capability,request_present) VALUES(?,?,?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET certificate=excluded.certificate,floor=excluded.floor,capability_sequence=excluded.capability_sequence,capability_digest=excluded.capability_digest,capability=excluded.capability,request_present=excluded.request_present`, a.device, a.certificate, strconv.FormatUint(a.floor, 10), strconv.FormatUint(a.capSequence, 10), a.capDigest, raw, a.request != nil); e != nil {
		return ErrStorage
	}
	var count int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_event_authority`).Scan(&count) != nil || count > 25 {
		return ErrWindowsEventCapacity
	}
	if a.request != nil {
		raw, e = windowseventrequest.Encode(*a.request)
		if e != nil {
			return ErrStorage
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_event_requests(device,body,result_digest,local_status) VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body,result_digest=excluded.result_digest,local_status=excluded.local_status`, a.device, raw, a.resultDigest, a.localStatus); e != nil {
			return ErrStorage
		}
	}
	return nil
}
func cancelWindowsEvent(a *windowsEventAuthority, now time.Time) error {
	if a.request == nil || a.request.State == windowseventrequest.Canceled || a.request.State == windowseventrequest.Expired {
		return nil
	}
	var r windowseventrequest.Record
	var e error
	if !now.Before(a.request.Description.ExpiresAt) {
		r, e = windowseventrequest.Expire(*a.request, now)
	} else {
		r, e = windowseventrequest.Cancel(*a.request, a.request.Description.Identity, now)
	}
	if e != nil {
		return e
	}
	a.request = &r
	return nil
}
func (s *Store) windowsEventIdentity(t *transaction, device, certificate string, now time.Time) (enrollmentstate.Snapshot, error) {
	for _, v := range t.engine.Snapshots() {
		if v.Approval.DeviceID != device {
			continue
		}
		if v.Platform != "windows" || v.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
			return v, ErrWindowsEventUnavailable
		}
		if certificate == "" {
			certificate = t.currentCertificateHash(v)
		}
		if err := t.authorizeCurrentCredential(v, certificate, now); err != nil {
			if errors.Is(err, ErrStorage) || errors.Is(err, enrollmentstate.ErrProof) || errors.Is(err, enrollmentstate.ErrInvalid) {
				return v, err
			}
			return v, ErrWindowsEventUnavailable
		}
		return v, nil
	}
	return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
}
func (s *Store) windowsEventCurrent(ctx context.Context, t *transaction, device, cert string, now time.Time) (enrollmentstate.Snapshot, windowsEventAuthority, error) {
	a, e := loadWindowsEventAuthority(ctx, t, device)
	if e != nil {
		return enrollmentstate.Snapshot{}, a, e
	}
	snap, e := s.windowsEventIdentity(t, device, cert, now)
	if e != nil {
		// A retired or mismatched transport leaf has no authority to cancel a
		// still-live anchor-bound request. Only identity expiry/revocation below
		// may persist the existing terminal cleanup.
		if errors.Is(e, enrollmentstate.ErrProof) || errors.Is(e, enrollmentstate.ErrInvalid) || errors.Is(e, ErrStorage) {
			return snap, a, e
		}
		if a.certificate != "" {
			if ce := cancelWindowsEvent(&a, now); ce != nil {
				return snap, a, ce
			}
			if ce := saveWindowsEventAuthority(ctx, t, a); ce != nil {
				return snap, a, ce
			}
		}
		return snap, a, e
	}
	if a.certificate != "" && a.certificate != snap.Issuance.CertificateHash {
		if e = cancelWindowsEvent(&a, now); e != nil {
			return snap, a, e
		}
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return snap, a, e
		}
		return snap, a, ErrWindowsEventUnavailable
	}
	if a.request != nil && !now.Before(a.request.Description.ExpiresAt) && a.request.State != windowseventrequest.Expired {
		r, e := windowseventrequest.Expire(*a.request, now)
		if e != nil {
			return snap, a, e
		}
		a.request = &r
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return snap, a, e
		}
	}
	if a.request != nil && !now.Before(a.request.Description.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge)) {
		if e = cancelWindowsEvent(&a, now); e != nil {
			return snap, a, e
		}
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return snap, a, e
		}
	}
	if e = purgeWindowsEventRequest(ctx, t, &a, now); e != nil {
		return snap, a, e
	}
	return snap, a, nil
}
func windowsEventLocal(a windowsEventAuthority, s enrollmentstate.Snapshot) windowseventrequest.LocalContext {
	return windowseventrequest.LocalContext{SenderBinding: a.capability.Consent.SenderBinding, Profile: s.Binding.Profile, DeviceID: s.Approval.DeviceID, CertificateHash: s.Issuance.CertificateHash}
}
func windowsEventReady(a windowsEventAuthority, now time.Time) error {
	if a.capability == nil || windowseventwire.CapabilityFresh(*a.capability, now) != nil {
		return ErrWindowsEventUnavailable
	}
	if !a.capability.Consent.Enabled {
		return windowseventrequest.ErrDisabled
	}
	return nil
}
func (s *Store) ReportWindowsEventCapability(ctx context.Context, device, cert string, c windowseventwire.Capability, now time.Time) (windowseventwire.Capability, error) {
	var out windowseventwire.Capability
	raw, e := windowseventwire.EncodeCapability(c)
	if e != nil || device != c.DeviceID || windowseventwire.CapabilityFresh(c, now) != nil {
		return out, windowseventrequest.ErrInvalid
	}
	e = s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		snap, e := s.windowsEventIdentity(t, device, cert, now)
		if e != nil {
			return e
		}
		if c.CertificateHash != snap.Issuance.CertificateHash {
			return enrollmentstate.ErrProof
		}
		if c.Consent.Profile != snap.Binding.Profile {
			return enrollmentstate.ErrProof
		}
		a, e := loadWindowsEventAuthority(ctx, t, device)
		if e != nil {
			return e
		}
		if c.Sequence < a.capSequence || c.Sequence == a.capSequence && windowsEventDigest(raw) != a.capDigest {
			return windowseventrequest.ErrConflict
		}
		if c.Sequence == a.capSequence {
			if a.capability == nil {
				return ErrWindowsEventUnavailable
			}
			out = *a.capability
			return nil
		}
		if a.capability != nil && c.CollectedAt.Before(a.capability.CollectedAt) {
			return windowseventrequest.ErrConflict
		}
		if a.capability != nil && (a.certificate != snap.Issuance.CertificateHash || c.PolicyDigest != a.capability.PolicyDigest) || !c.Consent.Enabled {
			if e = cancelWindowsEvent(&a, now); e != nil {
				return e
			}
		}
		credential := t.credentials[snap.InvitationID]
		credential.WindowsEventAuthorityInitialized = true
		t.credentials[snap.InvitationID] = credential
		a.certificate = snap.Issuance.CertificateHash
		a.capSequence = c.Sequence
		a.capDigest = windowsEventDigest(raw)
		a.capability = &c
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return e
		}
		out = c
		return nil
	})
	return out, e
}
func (s *Store) windowsEventHeaders(t *transaction, snap enrollmentstate.Snapshot, now time.Time) (*windowseventhealth.Snapshot, *WindowsEventHeaders, error) {
	c := t.credentials[snap.InvitationID]
	if len(c.Frame) == 0 {
		return nil, nil, nil
	}
	f, e := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
	if e != nil {
		return nil, nil, ErrStorage
	}
	h := f.WindowsEvents
	if h == nil || now.Before(h.CollectedAt) || !now.Before(h.CollectedAt.Add(windowseventrequest.MaxHeaderAge)) {
		return nil, nil, nil
	}
	raw, e := json.Marshal(h)
	if e != nil {
		return nil, nil, ErrStorage
	}
	return h, &WindowsEventHeaders{h.GenerationID, windowsEventDigest(raw), h.CollectedAt, h.CollectedAt.Add(windowseventrequest.MaxHeaderAge)}, nil
}
func (s *Store) WindowsEventContentStatus(ctx context.Context, device string, now time.Time) (WindowsEventStatus, error) {
	out := WindowsEventStatus{DeviceID: device, ExpectedFloor: "0", LocalStatus: "unavailable", ObservedAt: now}
	e := s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		snap, a, e := s.windowsEventCurrent(ctx, t, device, "", now)
		if e != nil {
			return e
		}
		out.ExpectedFloor = strconv.FormatUint(a.floor, 10)
		out.Capability = a.capability
		out.Request = a.request
		if windowseventwire.ValidLocalStatus(a.localStatus) {
			out.EndpointStatus = a.localStatus
		}
		out.AuthorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
		if a.capability != nil {
			out.LocalStatus = "enabled"
			if !a.capability.Consent.Enabled {
				out.LocalStatus = "disabled"
			} else if windowseventwire.CapabilityFresh(*a.capability, now) != nil {
				out.LocalStatus = "stale"
			}
		}
		if out.LocalStatus == "enabled" {
			_, out.Headers, e = s.windowsEventHeaders(t, snap, now)
		}
		return e
	})
	return out, e
}
func (s *Store) CreateWindowsEventRequest(ctx context.Context, device string, floor uint64, generation, digest string, selected []windowseventrequest.Selection, now time.Time) (windowseventrequest.Description, error) {
	var out windowseventrequest.Description
	e := s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		snap, a, e := s.windowsEventCurrent(ctx, t, device, "", now)
		if e != nil {
			return e
		}
		if e = windowsEventReady(a, now); e != nil {
			return e
		}
		if a.floor != floor || floor == math.MaxUint64 {
			return windowseventrequest.ErrConflict
		}
		if a.request != nil && (a.request.State == windowseventrequest.Pending || a.request.State == windowseventrequest.Claimed || a.request.State == windowseventrequest.Accepted) {
			return windowseventrequest.ErrConflict
		}
		headers, h, e := s.windowsEventHeaders(t, snap, now)
		if e != nil {
			return e
		}
		if h == nil {
			return ErrWindowsEventUnavailable
		}
		if h.GenerationID != generation || h.SnapshotDigest != digest {
			return windowseventrequest.ErrConflict
		}
		r, e := windowseventrequest.New(device, snap.Issuance.CertificateHash, floor+1, a.capability.Consent.GrantID, *headers, selected, now)
		if e != nil {
			return e
		}
		a.floor = floor + 1
		a.request = &r
		a.resultDigest = ""
		a.localStatus = "pending"
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return e
		}
		out = r.Description
		return nil
	})
	return out, e
}
func (s *Store) CancelWindowsEventRequest(ctx context.Context, device string, id windowseventrequest.Identity, now time.Time) error {
	return s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		_, a, e := s.windowsEventCurrent(ctx, t, device, "", now)
		if e != nil {
			return e
		}
		if a.request == nil || a.request.Description.Identity != id {
			return windowseventrequest.ErrConflict
		}
		if e = cancelWindowsEvent(&a, now); e != nil {
			return e
		}
		return saveWindowsEventAuthority(ctx, t, a)
	})
}
func (s *Store) PeekWindowsEventRequest(ctx context.Context, device, cert string, now time.Time) (*windowseventrequest.Description, error) {
	var out *windowseventrequest.Description
	e := s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		_, a, e := s.windowsEventCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if e = windowsEventReady(a, now); e != nil {
			return e
		}
		if a.request != nil && a.request.State == windowseventrequest.Pending {
			d := a.request.Description
			out = &d
		}
		return nil
	})
	return out, e
}
func (s *Store) ClaimWindowsEventRequest(ctx context.Context, device, cert string, claim windowseventwire.Claim, now time.Time) (windowseventwire.Grant, error) {
	var out windowseventwire.Grant
	e := s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		snap, a, e := s.windowsEventCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if e = windowsEventReady(a, now); e != nil {
			return e
		}
		if a.request == nil {
			return ErrWindowsEventUnavailable
		}
		expected, e := windowseventwire.ClaimFor(a.request.Description, a.capability.PolicyDigest)
		if e != nil || expected != claim {
			return windowseventrequest.ErrConflict
		}
		r, e := windowseventrequest.Claim(*a.request, claim.Identity, a.capability.Consent, windowsEventLocal(a, snap), now)
		if e != nil {
			return e
		}
		a.request = &r
		a.localStatus = "claimed"
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return e
		}
		out, e = windowseventwire.GrantFor(r)
		return e
	})
	return out, e
}

// The boolean is true only for the first committed result. Exact retries return
// the original receipt without permission to republish lost content.
func (s *Store) AcceptWindowsEventResult(ctx context.Context, device, cert string, result windowseventwire.Result, now time.Time) (windowseventrequest.Receipt, bool, error) {
	var out windowseventrequest.Receipt
	first := false
	e := s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		snap, a, e := s.windowsEventCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if e = windowsEventReady(a, now); e != nil {
			return e
		}
		if a.request == nil {
			return ErrWindowsEventUnavailable
		}
		if e = windowseventwire.ValidateResult(result, a.request.Description); e != nil {
			return e
		}
		d, e := windowseventwire.ResultDigest(result)
		if e != nil {
			return e
		}
		expected, e := windowseventwire.ClaimFor(a.request.Description, a.capability.PolicyDigest)
		if e != nil || expected != result.Claim {
			return windowseventrequest.ErrConflict
		}
		if a.request.State == windowseventrequest.Accepted {
			if a.resultDigest != d {
				return windowseventrequest.ErrConflict
			}
			out = *a.request.Receipt
			return nil
		}
		r, e := windowseventrequest.Accept(*a.request, result.Claim.Identity, a.capability.Consent, windowsEventLocal(a, snap), result.Report, now)
		if e != nil {
			return e
		}
		a.request = &r
		a.resultDigest = d
		a.localStatus = "accepted"
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return e
		}
		out = *r.Receipt
		first = true
		return nil
	})
	if e != nil {
		return windowseventrequest.Receipt{}, false, e
	}
	return out, first, nil
}
func (s *Store) ReportWindowsEventStatus(ctx context.Context, device, cert string, in windowseventwire.StatusInput, now time.Time) error {
	return s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		_, a, e := s.windowsEventCurrent(ctx, t, device, cert, now)
		if e != nil {
			return e
		}
		if a.request == nil || a.capability == nil {
			return ErrWindowsEventUnavailable
		}
		claim, e := windowseventwire.ClaimFor(a.request.Description, a.capability.PolicyDigest)
		if e != nil || claim != in.Claim {
			return windowseventrequest.ErrConflict
		}
		if e = windowseventrequest.CheckTime(*a.request, now); e != nil {
			return e
		}
		if !windowseventwire.ValidLocalStatus(in.LocalStatus) {
			return windowseventrequest.ErrInvalid
		}
		a.localStatus = in.LocalStatus
		if in.LocalStatus == "disabled" || in.LocalStatus == "expired" || in.LocalStatus == "canceled" || in.LocalStatus == "denied" || in.LocalStatus == "reader_unavailable" || in.LocalStatus == "result_lost" {
			if e = cancelWindowsEvent(&a, now); e != nil {
				return e
			}
		}
		return saveWindowsEventAuthority(ctx, t, a)
	})
}

// MaintainWindowsEventContent is also used at startup, when every pending or
// claimed request has lost its non-durable session owner.
func (s *Store) MaintainWindowsEventContent(ctx context.Context, now time.Time, abandon bool) error {
	return s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		_, err := s.maintainWindowsEventContent(ctx, t, now, abandon, nil)
		return err
	})
}

// MaintainWindowsEventAuthorities validates the complete store only once, then
// expires/purges authority and cancels unowned work in that same transaction.
// The caller holds the cache ownership mutex while taking and applying this
// exact-identity snapshot. Returned metadata is not a disclosure authorization;
// the cache must recheck its trusted clock and live sessions after the commit.
func (s *Store) MaintainWindowsEventAuthorities(ctx context.Context, live map[string]windowseventrequest.Identity, now time.Time) (map[string]WindowsEventStatus, error) {
	if live == nil {
		live = map[string]windowseventrequest.Identity{}
	}
	if len(live) > 25 {
		return nil, ErrWindowsEventCapacity
	}
	var out map[string]WindowsEventStatus
	err := s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		var err error
		out, err = s.maintainWindowsEventContent(ctx, t, now, false, live)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) maintainWindowsEventContent(ctx context.Context, t *transaction, now time.Time, abandon bool, live map[string]windowseventrequest.Identity) (map[string]WindowsEventStatus, error) {
	rows, e := t.conn.QueryContext(ctx, `SELECT device FROM enrollment_windows_event_authority ORDER BY device`)
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
	out := make(map[string]WindowsEventStatus, len(ids))
	for _, id := range ids {
		a, e := loadWindowsEventAuthority(ctx, t, id)
		if e != nil {
			return nil, e
		}
		snap, authorityErr := s.windowsEventIdentity(t, id, a.certificate, now)
		if authorityErr != nil && !errors.Is(authorityErr, ErrWindowsEventUnavailable) && !errors.Is(authorityErr, enrollmentstate.ErrNotFound) {
			return nil, authorityErr
		}
		unowned := a.request != nil && (abandon || live != nil && live[id] != a.request.Description.Identity) && (a.request.State == windowseventrequest.Pending || a.request.State == windowseventrequest.Claimed)
		if unowned || authorityErr != nil || a.request != nil && !now.Before(a.request.Description.ExpiresAt) {
			if e = cancelWindowsEvent(&a, now); e != nil {
				return nil, e
			}
		}
		if e = purgeWindowsEventRequest(ctx, t, &a, now); e != nil {
			return nil, e
		}
		// Expired report payloads can be purged without erasing replay floors.
		if a.capability != nil && !now.Before(a.capability.CollectedAt.Add(24*time.Hour)) {
			a.capability = nil
		}
		if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
			return nil, e
		}
		status := WindowsEventStatus{DeviceID: id, ExpectedFloor: strconv.FormatUint(a.floor, 10), LocalStatus: "unavailable", Request: a.request, Capability: a.capability, ObservedAt: now}
		if authorityErr == nil {
			status.AuthorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
			if a.capability != nil {
				status.LocalStatus = "enabled"
				if !a.capability.Consent.Enabled {
					status.LocalStatus = "disabled"
				} else if windowseventwire.CapabilityFresh(*a.capability, now) != nil {
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
func purgeWindowsEventRequest(ctx context.Context, t *transaction, a *windowsEventAuthority, now time.Time) error {
	if a.request == nil || now.Before(a.request.Description.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge)) {
		return nil
	}
	if _, e := t.conn.ExecContext(ctx, `DELETE FROM enrollment_windows_event_requests WHERE device=?`, a.device); e != nil {
		return ErrStorage
	}
	if _, e := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_event_authority SET request_present=0 WHERE device=?`, a.device); e != nil {
		return ErrStorage
	}
	a.request = nil
	a.resultDigest = ""
	a.localStatus = "unavailable"
	return nil
}

// Called while the cache holds its ownership mutex: create cannot install a
// new live owner between the snapshot and this durable cleanup transaction.
func (s *Store) CancelUnownedWindowsEventRequests(ctx context.Context, live map[string]windowseventrequest.Identity, now time.Time) error {
	return s.windowsEventTransaction(ctx, now, func(t *transaction) error {
		rows, e := t.conn.QueryContext(ctx, `SELECT device FROM enrollment_windows_event_requests ORDER BY device`)
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
			a, e := loadWindowsEventAuthority(ctx, t, id)
			if e != nil {
				return e
			}
			if a.request == nil || a.request.State != windowseventrequest.Pending && a.request.State != windowseventrequest.Claimed {
				continue
			}
			if expected, ok := live[id]; ok && expected == a.request.Description.Identity {
				continue
			}
			if e = cancelWindowsEvent(&a, now); e != nil {
				return e
			}
			if e = saveWindowsEventAuthority(ctx, t, a); e != nil {
				return e
			}
		}
		return nil
	})
}
