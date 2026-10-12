package windowsupdatejob

import (
	"bytes"
	"context"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
)

// ReadinessAttempt is one replaceable slot, independent of installation history.
// The manager signs a strictly increasing sequence, so a durable scalar floor
// rejects all older challenges without giving read-only checks a lifetime cap.
// A missing report means consumed without recoverable evidence, never retryable.
type ReadinessAttempt struct {
	Challenge []byte `json:"challenge"`
	ClaimedAt int64  `json:"claimedAt"`
	Report    []byte `json:"report"`
}

func (r ExecutorRecord) validateReadiness() error {
	a := r.LatestReadiness
	if a == nil {
		if r.ReadinessSequence != 0 {
			return ErrIntegrity
		}
		return nil
	}
	c, e := VerifyChallenge(a.Challenge, r.PublicKey)
	if e != nil || c.Binding != r.Consent.Binding || c.Sequence != r.ReadinessSequence || a.ClaimedAt < c.IssuedAt || a.ClaimedAt >= c.Deadline || a.ClaimedAt > r.ClockFloor {
		return ErrIntegrity
	}
	if len(a.Report) > 0 {
		s, e := VerifyStatement(a.Report, r.ExecutorPublicKey)
		if e != nil || s.Kind != "readiness" || s.Binding != r.Consent.Binding || s.JobID != c.JobID || s.ReferenceDigest != actionpermit.Digest(a.Challenge) || s.Deadline != c.Deadline || s.Readiness.Selection != c.Selection || s.IssuedAt < a.ClaimedAt || s.IssuedAt > r.ClockFloor || s.ExpiresAt > r.Consent.ExpiresAt {
			return ErrIntegrity
		}
	}
	return nil
}

func (r ExecutorRecord) validateResultReport(a Attempt, p Permit) error {
	if a.Result == nil {
		if len(a.ResultReport) != 0 {
			return ErrIntegrity
		}
		return nil
	}
	s, e := VerifyStatement(a.ResultReport, r.ExecutorPublicKey)
	if e != nil || s.Kind != "result" || s.Binding != r.Consent.Binding || s.JobID != p.Preview.ID || s.ReferenceDigest != actionpermit.Digest(a.Envelope) || s.Deadline != p.Preview.ExpiresAt || *s.Result != *a.Result {
		return ErrIntegrity
	}
	return nil
}

func (x *Executor) currentAuthority(c Current) (int64, error) {
	n, e := x.observeTime()
	if e != nil {
		return n, e
	}
	if c.Binding != x.record.Consent.Binding || !c.Enabled || c.Revoked || !actionpermit.ValidDigest(c.LeafDigest) || c.LeafGeneration == 0 || !x.record.Consent.Enabled || !x.record.Consent.Acknowledged {
		return n, x.rejectTime(n, ErrAuthority)
	}
	if n < x.record.ClockFloor || !validTime(c.LeafNotBefore) || !validTime(c.LeafNotAfter) || n < c.LeafNotBefore || n >= c.LeafNotAfter || n >= x.record.Consent.ExpiresAt {
		return n, x.rejectTime(n, ErrExpired)
	}
	return n, nil
}
func (x *Executor) currentChallenge(c Current, challenge Challenge) (int64, error) {
	n, e := x.currentAuthority(c)
	if e != nil {
		return n, e
	}
	if challenge.Binding != c.Binding {
		return n, x.rejectTime(n, ErrAuthority)
	}
	if n < challenge.IssuedAt || n >= challenge.Deadline {
		return n, x.rejectTime(n, ErrExpired)
	}
	return n, nil
}

// Readiness verifies and durably consumes the manager's exact signed challenge
// before any injected adapter access. PrepareExact/Inspect/Close are the only
// adapter methods called; this path cannot dispatch installation. A lost reply
// is recoverable only from the original saved report through Outbox, never by
// resolving or signing again. No key, grant, state file or host IPC is created.
func (x *Executor) Readiness(ctx context.Context, raw []byte) ([]byte, error) {
	if x == nil || !x.mu.TryLock() {
		return nil, ErrConflict
	}
	defer x.mu.Unlock()
	if ctx == nil {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := x.check(); e != nil {
		return nil, e
	}
	if _, e := x.observeTime(); e != nil {
		return nil, e
	}
	if x.accepted != nil || x.running {
		return nil, ErrConflict
	}
	for _, a := range x.record.Attempts {
		if a.Result == nil || a.Result.Outcome == "uncertain" || a.Result.Outcome == "failed" {
			return nil, ErrConflict
		}
	}
	challenge, e := VerifyChallenge(raw, x.record.PublicKey)
	if e != nil {
		return nil, e
	}
	if challenge.Binding != x.record.Consent.Binding {
		return nil, ErrAuthority
	}
	if challenge.Sequence <= x.record.ReadinessSequence {
		return nil, ErrConsumed
	}
	var readiness Readiness
	var sourceAt int64
	e = x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		n, err := x.currentChallenge(c, challenge)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		x.record.ReadinessSequence = challenge.Sequence
		x.record.LatestReadiness = &ReadinessAttempt{Challenge: bytes.Clone(raw), ClaimedAt: n}
		if err = x.save(); err != nil {
			return err
		}
		// Durable storage may take time. Recheck the original authority/deadline
		// inside the same local credential fence immediately before source access.
		if sourceAt, err = x.currentChallenge(c, challenge); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		prepared, err := x.adapter.PrepareExact(ctx, challenge.Selection)
		if err != nil || prepared == nil {
			if prepared != nil {
				_ = prepared.Close()
			}
			return ErrUnavailable
		}
		readiness, err = prepared.Inspect(ctx)
		closeErr := prepared.Close()
		if err != nil || closeErr != nil {
			return ErrUnavailable
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	var out []byte
	e = x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		if err := x.check(); err != nil {
			return err
		}
		n, err := x.currentChallenge(c, challenge)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if readiness.Validate() != nil || readiness.Selection != challenge.Selection || readiness.CapturedAt < sourceAt || readiness.CapturedAt > n || n-readiness.CapturedAt >= 60 {
			return ErrInvalid
		}
		expires := min(readiness.CapturedAt+60, challenge.Deadline, x.record.Consent.ExpiresAt, c.LeafNotAfter)
		if n >= expires {
			return x.rejectTime(n, ErrExpired)
		}
		report, err := SignStatement(Statement{Version: RelayVersion, Kind: "readiness", Binding: challenge.Binding, JobID: challenge.JobID, ReferenceDigest: actionpermit.Digest(raw), Deadline: challenge.Deadline, IssuedAt: readiness.CapturedAt, ExpiresAt: expires, Readiness: &readiness}, x.key)
		if err != nil {
			return err
		}
		x.record.LatestReadiness.Report = report
		if err = x.save(); err != nil {
			return err
		}
		n, err = x.currentChallenge(c, challenge)
		if err != nil {
			return err
		}
		if n >= expires {
			return x.rejectTime(n, ErrExpired)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		out = bytes.Clone(report)
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}

// EvidenceStatus contains reconciliation metadata, never an execution envelope,
// statement signature, signing key or source error prose. Missing evidence is
// explicit and is not a request to repeat source access or installation.
type EvidenceStatus struct {
	Kind            string    `json:"kind"`
	JobID           string    `json:"jobId"`
	ReferenceDigest string    `json:"referenceDigest"`
	Selection       Selection `json:"selection"`
	Sequence        uint64    `json:"sequence,string"`
	Deadline        int64     `json:"deadline"`
	ClaimedAt       int64     `json:"claimedAt"`
	Attempted       bool      `json:"attempted"`
	Result          *Result   `json:"result"`
	ReportState     string    `json:"reportState"`
	ReportIssuedAt  int64     `json:"reportIssuedAt"`
	ReportExpiresAt int64     `json:"reportExpiresAt"`
}
type ExecutorStatus struct {
	ObservedAt               int64            `json:"observedAt"`
	ReadinessSequence        uint64           `json:"readinessSequence,string"`
	InstallSequence          uint64           `json:"installSequence,string"`
	InstallCapacityRemaining int              `json:"installCapacityRemaining"`
	InterventionRequired     bool             `json:"interventionRequired"`
	Readiness                *EvidenceStatus  `json:"readiness"`
	Attempts                 []EvidenceStatus `json:"attempts"`
}

func reportStatus(s *EvidenceStatus, raw []byte, key []byte, now int64) {
	s.ReportState = "missing"
	if len(raw) == 0 {
		return
	}
	report, _ := VerifyStatement(raw, key) // The protected record was validated.
	s.ReportIssuedAt, s.ReportExpiresAt = report.IssuedAt, report.ExpiresAt
	s.ReportState = "available"
	if now >= report.ExpiresAt {
		s.ReportState = "expired"
	}
}

// Status is operation-read-only: it retains only the monotonic observation
// clock floor. It never repairs state, signs a report or calls an adapter. The
// original permit digest and completed timestamp support exact reconciliation.
func (x *Executor) Status(ctx context.Context) (ExecutorStatus, error) {
	if x == nil || !x.mu.TryLock() {
		return ExecutorStatus{}, ErrConflict
	}
	defer x.mu.Unlock()
	var out ExecutorStatus
	e := x.readCurrent(ctx, func(n int64) error {
		out = ExecutorStatus{ObservedAt: n, ReadinessSequence: x.record.ReadinessSequence, InstallSequence: x.record.Sequence, InstallCapacityRemaining: MaxJobs - len(x.record.Attempts), Attempts: []EvidenceStatus{}}
		if a := x.record.LatestReadiness; a != nil {
			c, _ := VerifyChallenge(a.Challenge, x.record.PublicKey)
			s := &EvidenceStatus{Kind: "readiness", JobID: c.JobID, ReferenceDigest: actionpermit.Digest(a.Challenge), Selection: c.Selection, Sequence: c.Sequence, Deadline: c.Deadline, ClaimedAt: a.ClaimedAt}
			reportStatus(s, a.Report, x.record.ExecutorPublicKey, n)
			out.Readiness = s
		}
		for _, a := range x.record.Attempts {
			p, _ := Verify(a.Envelope, x.record.PublicKey)
			s := EvidenceStatus{Kind: "result", JobID: p.Preview.ID, ReferenceDigest: actionpermit.Digest(a.Envelope), Selection: p.Preview.Readiness.Selection, Sequence: p.Sequence, Deadline: p.Preview.ExpiresAt, ClaimedAt: a.ClaimedAt, Attempted: a.Attempted}
			if a.Result != nil {
				r := *a.Result
				s.Result = &r
			}
			reportStatus(&s, a.ResultReport, x.record.ExecutorPublicKey, n)
			out.Attempts = append(out.Attempts, s)
			if a.Result == nil || a.Result.Outcome == "uncertain" || a.Result.Outcome == "failed" {
				out.InterventionRequired = true
			}
		}
		return nil
	})
	if e != nil {
		return ExecutorStatus{}, e
	}
	return out, nil
}

func (x *Executor) readCurrent(ctx context.Context, fn func(int64) error) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := x.check(); e != nil {
		return e
	}
	if _, e := x.observeTime(); e != nil {
		return e
	}
	return x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		n, e := x.currentAuthority(c)
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		return fn(n)
	})
}

// Outbox returns only the exact bytes already durably signed with the original
// issue/completion time. Expired evidence remains visible in Status but is not
// renewed or delivered as a fresh report. No acknowledgement deletes evidence.
// A missing report after a crash cannot be regenerated, even from a saved result.
func (x *Executor) Outbox(ctx context.Context, kind, jobID, referenceDigest string) ([]byte, error) {
	if x == nil || !x.mu.TryLock() {
		return nil, ErrConflict
	}
	defer x.mu.Unlock()
	if (kind != "readiness" && kind != "result") || !enrollmentcrypto.ValidID(jobID, "update_") || !actionpermit.ValidDigest(referenceDigest) {
		return nil, ErrInvalid
	}
	var out []byte
	e := x.readCurrent(ctx, func(n int64) error {
		var raw []byte
		if kind == "readiness" {
			if a := x.record.LatestReadiness; a != nil {
				c, _ := VerifyChallenge(a.Challenge, x.record.PublicKey)
				if c.JobID == jobID {
					raw = a.Report
				}
			}
		} else {
			for _, a := range x.record.Attempts {
				p, _ := Verify(a.Envelope, x.record.PublicKey)
				if p.Preview.ID == jobID {
					raw = a.ResultReport
					break
				}
			}
		}
		if len(raw) == 0 {
			return ErrUnavailable
		}
		s, err := VerifyStatement(raw, x.record.ExecutorPublicKey)
		if err != nil {
			return ErrIntegrity
		}
		if s.ReferenceDigest != referenceDigest {
			return ErrConflict
		}
		if n < s.IssuedAt || n >= s.ExpiresAt {
			return x.rejectTime(n, ErrExpired)
		}
		out = bytes.Clone(raw)
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
