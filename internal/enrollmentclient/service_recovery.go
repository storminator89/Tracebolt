package enrollmentclient

import (
	"context"
	"time"
)

// Only ResumeServiceRecovery can introduce this authority. The original binding
// is checked under the enrollment lease before installing its write guard.
type serviceRecoveryAuthority struct {
	binding  string
	deadline int64
	ctx      context.Context
	now      func() time.Time
}

func (a *serviceRecoveryAuthority) guard() error {
	if a == nil || a.ctx == nil || a.now == nil {
		return ErrState
	}
	if a.now().Unix() >= a.deadline {
		return ErrServiceDeadline
	}
	return a.ctx.Err()
}

type recoveryEnrollmentStorage struct {
	enrollmentStorage
	guard func() error
}

func (s recoveryEnrollmentStorage) Write(name string, raw []byte) error {
	if err := s.guard(); err != nil {
		return err
	}
	return s.enrollmentStorage.Write(name, raw)
}
func (s recoveryEnrollmentStorage) EnsureTelemetry() error {
	if err := s.guard(); err != nil {
		return err
	}
	return s.enrollmentStorage.EnsureTelemetry()
}

func (s *session) guardRecoveryWrite() error {
	if s.opts.recovery == nil {
		return nil
	}
	return s.opts.recovery.guard()
}

// ResumeServiceRecovery retains the ordinary protocol and exact retry bytes,
// but also fences active-identity writes by the original pending deadline.
// Ordinary ResumeService and normal ready startup retain their old semantics.
func ResumeServiceRecovery(ctx context.Context, b Bootstrap, state string, expected ServiceRecoveryState) (Result, error) {
	if ctx == nil || b.Profile != "tls" || b.RenewalPolicy != "" || len(expected.Binding) != 64 {
		return Result{}, ErrBootstrap
	}
	if time.Now().Unix() >= expected.DeadlineAt {
		return Result{}, ErrServiceDeadline
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(expected.DeadlineAt, 0))
	defer cancel()
	result, err := Run(bounded, b, Options{StateDirectory: state, ResumeOnly: true, Display: func(TrustDisplay) error { return nil }, recovery: &serviceRecoveryAuthority{expected.Binding, expected.DeadlineAt, bounded, time.Now}})
	if err != nil {
		return Result{}, err
	}
	// Run closes the store before returning. Its inner session context is then
	// intentionally canceled, so use this original bounded context for the final
	// completion check rather than the authority's replaced session context.
	if time.Now().Unix() >= expected.DeadlineAt {
		return Result{}, ErrServiceDeadline
	}
	if err = bounded.Err(); err != nil {
		return Result{}, err
	}
	return result, nil
}
