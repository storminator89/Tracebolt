package enrollmentstore

import (
	"context"
	"errors"
	"slices"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
)

const JournalGenerationMaxAge = 5 * time.Minute

var ErrJournalGenerationStale = errors.New("journal_generation_stale")

// This identity-bound floor is never pruned with inventory or content. Exact
// retries preserve Report, ReceivedAt and a latched expiration unchanged.
type journalGenerationRecord struct {
	DeviceID        string                   `json:"deviceId"`
	CertificateHash string                   `json:"certificateHash"`
	Report          journalgeneration.Report `json:"report"`
	ReceivedAt      time.Time                `json:"receivedAt"`
	ExpiredAt       *time.Time               `json:"expiredAt,omitempty"`
}

// JournalGenerationView exposes the acknowledged, generation-bound summary.
// Legacy v1 reports have no summary. Historical metadata is never live authority.
// Fresh means eligible for a generation-bound request, not permission to read.
type JournalGenerationView struct {
	SchemaVersion        string                                 `json:"schemaVersion"`
	PolicyGeneration     journalgeneration.Tuple                `json:"policyGeneration"`
	Sequence             uint64                                 `json:"sequence,string"`
	ObservedAt           time.Time                              `json:"observedAt"`
	ReceivedAt           time.Time                              `json:"receivedAt"`
	ExpiresAt            time.Time                              `json:"expiresAt"`
	Fresh                bool                                   `json:"fresh"`
	PolicyEnabled        *bool                                  `json:"policyEnabled,omitempty"`
	ServiceAuthorization journalgeneration.ServiceAuthorization `json:"serviceAuthorization,omitempty"`
	AllowedUnits         *[]string                              `json:"allowedUnits,omitempty"`
}

func validJournalGeneration(snap enrollmentstate.Snapshot, r journalGenerationRecord) bool {
	if journalgeneration.ValidateReport(r.Report) != nil || r.DeviceID != snap.Approval.DeviceID || !enrollmentcrypto.ValidHash(r.CertificateHash) || !validStoreTime(r.ReceivedAt) || r.ReceivedAt.Location() != time.UTC || r.Report.ObservedAt.After(r.ReceivedAt) || r.ReceivedAt.Sub(r.Report.ObservedAt) >= JournalGenerationMaxAge || r.ReceivedAt.Unix() < snap.Activation.At || r.ReceivedAt.Unix() >= snap.Intent.NotAfter || r.Report.ObservedAt.Unix() < snap.Activation.At || r.Report.ObservedAt.Add(JournalGenerationMaxAge).Year() > 9999 || snap.Termination.At != 0 && r.ReceivedAt.Unix() > snap.Termination.At {
		return false
	}
	return r.ExpiredAt == nil || validStoreTime(*r.ExpiredAt) && r.ExpiredAt.Location() == time.UTC && !r.ExpiredAt.Before(r.Report.ObservedAt.Add(JournalGenerationMaxAge)) && r.ExpiredAt.Unix() < snap.Intent.NotAfter && (snap.Termination.At == 0 || r.ExpiredAt.Unix() <= snap.Termination.At)
}
func journalGenerationIdentity(r *journalGenerationRecord, snap enrollmentstate.Snapshot) error {
	if r != nil && (r.DeviceID != snap.Approval.DeviceID || r.CertificateHash != snap.Issuance.CertificateHash) {
		return enrollmentstate.ErrProof
	}
	return nil
}
func currentJournalGeneration(system systemRecord, snap enrollmentstate.Snapshot, d journalrequest.Description) error {
	r := system.JournalGeneration
	if err := journalGenerationIdentity(r, snap); err != nil {
		return err
	}
	if r == nil {
		if d.SchemaVersion != journalrequest.SchemaVersion {
			return journalrequest.ErrConflict
		}
		return nil
	}
	if d.SchemaVersion != journalrequest.SchemaVersionV2 || d.PolicyGeneration != r.Report.Tuple {
		return journalrequest.ErrConflict
	}
	return nil
}

// AcceptJournalGeneration is called only with a transport-authenticated leaf.
// The tuple floor, sequence, request cancellation and identity recheck commit in
// the same manager-authority transaction. A report never creates a capture.
func (s *Store) AcceptJournalGeneration(ctx context.Context, id, hash string, report journalgeneration.Report, now time.Time) (journalgeneration.Report, error) {
	var out journalgeneration.Report
	now = now.UTC()
	report = journalgeneration.CloneReport(report)
	err := s.journalTransaction(ctx, now, func(t *transaction) error {
		snap, system, err := s.journalAuthority(t, id, hash, now)
		if err != nil {
			return err
		}
		if journalgeneration.ValidateReport(report) != nil {
			return journalrequest.ErrInvalid
		}
		prior := system.JournalGeneration
		if err = journalGenerationIdentity(prior, snap); err != nil {
			return err
		}
		if prior != nil {
			old := prior.Report
			if report.Tuple == old.Tuple && !journalgeneration.SameAuthorization(report, old) || old.SchemaVersion == journalgeneration.ReportVersionV2 && report.SchemaVersion != journalgeneration.ReportVersionV2 {
				return journalrequest.ErrConflict
			}
			if report.Sequence < old.Sequence || report.Tuple.Revision < old.Tuple.Revision || report.Tuple.Revision == old.Tuple.Revision && report.Tuple != old.Tuple {
				return journalrequest.ErrConflict
			}
			if report.Tuple.Revision > old.Tuple.Revision && (report.Tuple.Generation == old.Tuple.Generation || report.Tuple.PolicyDigest == old.Tuple.PolicyDigest) {
				return journalrequest.ErrConflict
			}
			if report.Sequence == old.Sequence {
				if !journalgeneration.EqualReport(report, old) {
					return journalrequest.ErrConflict
				}
				// Receipt and report bytes stay original. A safely observed
				// expiry may only latch the independent freshness gate.
				if _, err = s.journalGenerationFresh(ctx, t, snap, system, now); err != nil {
					return err
				}
				out = journalgeneration.CloneReport(old)
				return nil
			}
			if !report.ObservedAt.After(old.ObservedAt) || now.Before(prior.ReceivedAt) || prior.ExpiredAt != nil && now.Before(*prior.ExpiredAt) {
				return journalrequest.ErrConflict
			}
		}
		if report.ObservedAt.After(now) || !now.Before(report.ObservedAt.Add(JournalGenerationMaxAge)) {
			return ErrJournalGenerationStale
		}
		next := &journalGenerationRecord{DeviceID: snap.Approval.DeviceID, CertificateHash: hash, Report: report, ReceivedAt: now}
		if !validJournalGeneration(snap, *next) {
			return journalrequest.ErrInvalid
		}
		system.JournalGeneration = next
		if prior == nil || prior.Report.Tuple != report.Tuple {
			if old := system.JournalRequest; old != nil && (old.State == journalrequest.Pending || old.State == journalrequest.Claimed) {
				query := *old
				if now.Before(query.Description.ExpiresAt) {
					query.State, query.CanceledAt = journalrequest.Canceled, &now
				} else {
					query.State, query.ExpiredAt = journalrequest.Expired, &now
				}
				system.JournalRequest = &query
			}
		}
		if err = s.saveJournalSystem(ctx, t, snap, system); err != nil {
			return err
		}
		out = journalgeneration.CloneReport(report)
		return nil
	})
	if err != nil {
		return journalgeneration.Report{}, err
	}
	return out, nil
}

func (s *Store) journalGenerationFresh(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, system systemRecord, now time.Time) (bool, error) {
	r := system.JournalGeneration
	if err := journalGenerationIdentity(r, snap); err != nil {
		return false, err
	}
	if r == nil {
		return false, nil
	}
	if now.Before(r.ReceivedAt) {
		return false, journalrequest.ErrInvalid
	}
	if r.ExpiredAt != nil {
		return false, nil
	}
	if now.Before(r.Report.ObservedAt.Add(JournalGenerationMaxAge)) {
		return true, nil
	}
	updated := *r
	updated.ExpiredAt = &now
	system.JournalGeneration = &updated
	if err := s.saveJournalSystem(ctx, t, snap, system); err != nil {
		return false, err
	}
	return false, nil
}
func (s *Store) checkJournalGenerationCreate(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, system systemRecord, expected journalgeneration.Tuple, now time.Time) error {
	r := system.JournalGeneration
	if r == nil {
		if expected != (journalgeneration.Tuple{}) {
			return journalrequest.ErrConflict
		}
		return nil
	}
	if journalgeneration.Validate(expected) != nil || expected != r.Report.Tuple {
		return journalrequest.ErrConflict
	}
	fresh, err := s.journalGenerationFresh(ctx, t, snap, system, now)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrJournalGenerationStale
	}
	return nil
}
func (s *Store) JournalGenerationStatus(ctx context.Context, device string, now time.Time) (*JournalGenerationView, error) {
	release, err := s.systemReadAdmission(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	var out *JournalGenerationView
	var certificateNotAfter int64
	now = now.UTC()
	read := func(t *transaction) error {
		var err error
		now, err = systemViewNow(ctx, now)
		if err != nil {
			return err
		}
		out = nil
		snap, system, err := s.journalOperatorAuthority(t, device, now)
		if err != nil {
			return err
		}
		certificateNotAfter = snap.Intent.NotAfter
		r := system.JournalGeneration
		if r == nil {
			return nil
		}
		fresh, err := s.journalGenerationFresh(ctx, t, snap, system, now)
		if err != nil {
			return err
		}
		out = &JournalGenerationView{SchemaVersion: "tracebolt.journal-generation-view.v1", PolicyGeneration: r.Report.Tuple, Sequence: r.Report.Sequence, ObservedAt: r.Report.ObservedAt, ReceivedAt: r.ReceivedAt, ExpiresAt: r.Report.ObservedAt.Add(JournalGenerationMaxAge), Fresh: fresh}
		if r.Report.SchemaVersion == journalgeneration.ReportVersionV2 {
			out.SchemaVersion = "tracebolt.journal-generation-view.v2"
			enabled, units := r.Report.PolicyEnabled, slices.Clone(r.Report.AllowedUnits)
			out.PolicyEnabled, out.ServiceAuthorization, out.AllowedUnits = &enabled, r.Report.ServiceAuthorization, &units
		}
		return nil
	}
	err = s.transact(ctx, read)
	if err != nil {
		return nil, err
	}
	now, err = journalReadCheckedNow(ctx, now, certificateNotAfter)
	if err != nil {
		return nil, err
	}
	if out != nil && out.Fresh && !now.Before(out.ExpiresAt) {
		// Latch an expiry crossed by COMMIT using the existing write, without
		// releasing/reacquiring admission or retrying a failed transaction.
		if err = s.transact(ctx, read); err != nil {
			return nil, err
		}
		now, err = journalReadCheckedNow(ctx, now, certificateNotAfter)
		if err != nil {
			return nil, err
		}
		if out != nil && out.Fresh && !now.Before(out.ExpiresAt) {
			return nil, ErrJournalGenerationStale
		}
	}
	return out, nil
}
