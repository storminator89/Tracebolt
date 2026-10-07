package enrollmentclient

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const serviceMarkerName = "service-enrollment.json"
const serviceMarkerVersion = "tracebolt.pending-service-enrollment.v1"

var ErrServiceDeadline = errors.New("saved pending-service deadline passed; retain state for manual recovery")

type serviceEnrollment struct {
	Version             string                `json:"version"`
	Mode                string                `json:"mode"`
	BootstrapHash       string                `json:"bootstrapHash"`
	ClaimID             string                `json:"claimId"`
	ClaimRequestID      string                `json:"claimRequestId"`
	KeyFingerprint      string                `json:"keyFingerprint"`
	CSRHash             string                `json:"csrHash"`
	ClaimHash           string                `json:"claimHash"`
	ClaimAt             int64                 `json:"claimAt"`
	DeadlineStopped     bool                  `json:"deadlineStopped"`
	DeadlineAt          int64                 `json:"deadlineAt"`
	LastRevision        uint64                `json:"lastRevision"`
	LastState           enrollmentstate.State `json:"lastState"`
	ReadyObserved       bool                  `json:"readyObserved"`
	ServerAuthenticated bool                  `json:"serverAuthenticated"`
}

func serviceTerminal(state enrollmentstate.State) bool {
	return state == enrollmentstate.Expired || state == enrollmentstate.Canceled || state == enrollmentstate.Rejected || state == enrollmentstate.Revoked
}
func serviceRank(state enrollmentstate.State) int {
	switch state {
	case enrollmentstate.ClaimedPending:
		return 1
	case enrollmentstate.Approved:
		return 2
	case enrollmentstate.IssuanceIntent:
		return 3
	case enrollmentstate.Issued:
		return 4
	case enrollmentstate.Activated:
		return 5
	}
	return 0
}
func (s *session) markerBinding() serviceEnrollment {
	raw, _ := json.Marshal(s.l.Bootstrap)
	return serviceEnrollment{Version: serviceMarkerVersion, Mode: "pending-service-v2", BootstrapHash: fingerprint(raw), ClaimID: s.l.ClaimID, ClaimRequestID: s.l.ClaimRequestID, KeyFingerprint: fingerprint(s.publicDER), CSRHash: fingerprint(s.csr), ClaimHash: s.l.ClaimHash, ServerAuthenticated: s.l.Bootstrap.Profile == "tls"}
}
func (s *session) loadService(required bool) error {
	raw, err := s.store.Read(serviceMarkerName)
	if errors.Is(err, os.ErrNotExist) {
		if required {
			return ErrState
		}
		return nil
	}
	if err != nil {
		return ErrState
	}
	defer clear(raw)
	var m serviceEnrollment
	if strictJSON(raw, &m) != nil {
		return ErrState
	}
	want := s.markerBinding()
	if !s.l.ClaimConfirmed || m.Version != want.Version || m.Mode != want.Mode || m.BootstrapHash != want.BootstrapHash || m.ClaimID != want.ClaimID || m.ClaimRequestID != want.ClaimRequestID || m.KeyFingerprint != want.KeyFingerprint || m.CSRHash != want.CSRHash || m.ClaimHash != want.ClaimHash || m.ServerAuthenticated != want.ServerAuthenticated || m.ClaimAt <= 0 || m.DeadlineAt <= m.ClaimAt || m.DeadlineAt-m.ClaimAt > enrollmentstate.MaxPendingTTL || m.DeadlineAt > enrollmentstate.MaxTimestamp || m.LastRevision == 0 || m.LastRevision > s.l.LastRevision || serviceRank(m.LastState) == 0 && !serviceTerminal(m.LastState) {
		return ErrState
	}
	if m.ReadyObserved && (!s.l.Activated || !s.l.HandoffPrepared || !s.l.SenderInitializationStarted || m.LastState != enrollmentstate.Activated && !serviceTerminal(m.LastState)) {
		return ErrState
	}
	if m.ReadyObserved {
		raw, readyErr := s.store.Read("ready.json")
		clear(raw)
		if readyErr != nil || lanclient.ValidateGuidedHandoff(filepath.Join(s.opts.StateDirectory, "agent.json")) != nil {
			return ErrState
		}
	}
	s.service = &m
	if serviceTerminal(m.LastState) {
		return ErrTerminal
	}
	return nil
}
func (s *session) saveService() error {
	if s.service == nil {
		return ErrState
	}
	raw, err := json.Marshal(s.service)
	if err != nil {
		return ErrState
	}
	return s.store.Write(serviceMarkerName, raw)
}
func (s *session) recordServiceSnapshot(v enrollmentstate.Snapshot, allowCreate bool) error {
	if !s.l.ClaimConfirmed || v.Revision != s.l.LastRevision || v.Claim.ClaimHash != s.l.ClaimHash {
		return ErrState
	}
	if s.service == nil {
		if !allowCreate {
			return ErrState
		}
		m := s.markerBinding()
		m.DeadlineAt = v.DeadlineAt
		m.ClaimAt = v.Claim.At
		s.service = &m
	}
	m := s.service
	if serviceTerminal(m.LastState) || v.Claim.At != m.ClaimAt || v.DeadlineAt != m.DeadlineAt || v.Revision < m.LastRevision || v.Revision == m.LastRevision && v.State != m.LastState || !serviceTerminal(v.State) && serviceRank(v.State) < serviceRank(m.LastState) {
		return ErrState
	}
	m.LastRevision = v.Revision
	m.LastState = v.State
	return s.saveService()
}

// Pending expiry is a local bounded stop, never proof of server expiry. In
// particular an unacknowledged activation across this deadline is manual-only.
func (s *session) checkServiceDeadline(now time.Time) error {
	if s.service == nil {
		return nil
	}
	if serviceTerminal(s.service.LastState) {
		return ErrTerminal
	}
	if s.service.DeadlineStopped {
		return ErrServiceDeadline
	}
	if s.l.Activated {
		if s.l.Intent.NotAfter <= now.Unix() {
			return ErrServiceDeadline
		}
		return nil
	}
	if now.Unix() >= s.service.DeadlineAt {
		return ErrServiceDeadline
	}
	if s.l.Intent.NotAfter != 0 && now.Unix() >= s.l.Intent.NotAfter {
		return ErrServiceDeadline
	}
	return nil
}

// ServiceState contains no key, invitation secret or raw observation. Ready is
// established locally; pending/active transport phases never imply collection.
type ServiceState struct {
	Ready      bool
	ConfigPath string
	HTTPTest   bool
}

func withServiceSession(b Bootstrap, state string, insecure bool, fn func(*session) (ServiceState, error)) (ServiceState, error) {
	if validatePlatformBootstrap(b, runtime.GOOS) != nil {
		return ServiceState{}, ErrBootstrap
	}
	if (b.Profile == "http-test") != insecure {
		return ServiceState{}, ErrBootstrap
	}
	trust, err := validateBootstrap(b, time.Now())
	if err != nil {
		return ServiceState{}, err
	}
	st, err := openExistingStore(state)
	if err != nil {
		return ServiceState{}, err
	}
	defer st.Close()
	s := &session{&sessionData{store: st, opts: Options{StateDirectory: state, InsecureHTTPAcknowledged: insecure, ResumeOnly: true}, trust: trust}}
	defer func() { clear(s.key) }()
	if err = s.load(b); err != nil {
		return ServiceState{}, err
	}
	if err = s.loadService(true); err != nil {
		return ServiceState{}, err
	}
	return fn(s)
}
func (s *session) inspectService() (ServiceState, error) {
	out := ServiceState{ConfigPath: filepath.Join(s.opts.StateDirectory, "agent.json"), HTTPTest: s.l.Bootstrap.Profile == "http-test"}
	if err := s.checkServiceDeadline(time.Now()); err != nil {
		return ServiceState{}, err
	}
	raw, err := s.store.Read("ready.json")
	clear(raw)
	if err == nil {
		if !s.l.Activated || !s.l.HandoffPrepared || s.service.LastState != enrollmentstate.Activated || s.service.LastRevision != s.l.LastRevision || lanclient.ValidateGuidedHandoff(out.ConfigPath) != nil {
			return ServiceState{}, ErrState
		}
		out.Ready = true
		return out, nil
	}
	if !errors.Is(err, os.ErrNotExist) || s.service.ReadyObserved {
		return ServiceState{}, ErrState
	}
	return out, nil
}

// InspectService is read-only under the existing enrollment lock. Callers must
// first enforce their numeric service UID/GID policy. It never creates files,
// keys, counters, folders, locks, polls the manager or constructs a collector.
func InspectService(b Bootstrap, state string, insecure bool) (ServiceState, error) {
	return withServiceSession(b, state, insecure, func(s *session) (ServiceState, error) { return s.inspectService() })
}

// MarkServiceReady is deliberately separate from offline installer inspection.
// The service invokes it after complete handoff/ledger validation and before
// sender construction. ReadyObserved is monotonic and never repaired/reset.
func MarkServiceReady(b Bootstrap, state string, insecure bool) (ServiceState, error) {
	return withServiceSession(b, state, insecure, func(s *session) (ServiceState, error) {
		out, err := s.inspectService()
		if err != nil || !out.Ready {
			return ServiceState{}, ErrState
		}
		if !s.service.ReadyObserved {
			s.service.ReadyObserved = true
			if err = s.saveService(); err != nil {
				return ServiceState{}, err
			}
		}
		return out, nil
	})
}

// ResumeService completes only a previously committed pending operation. Normal
// Ready startup uses InspectService instead, so manager availability is not an
// additional boot requirement. No invitation callback or new identity is used.
func ResumeService(ctx context.Context, b Bootstrap, state string, insecure bool, notify func(Progress) error) (Result, error) {
	return Run(ctx, b, Options{StateDirectory: state, InsecureHTTPAcknowledged: insecure, ResumeOnly: true, Display: func(TrustDisplay) error { return nil }, Notify: notify})
}

func (s *session) enforceServiceDeadline(now time.Time) error {
	err := s.checkServiceDeadline(now)
	if errors.Is(err, ErrServiceDeadline) && s.service != nil && !s.service.DeadlineStopped {
		s.service.DeadlineStopped = true
		if saveErr := s.saveService(); saveErr != nil {
			return saveErr
		}
	}
	return err
}

// StopServiceAtDeadline records a one-way local stop. It is not a claim that the
// manager proved expiry, and never permits a new identity or deadline extension.
func StopServiceAtDeadline(b Bootstrap, state string, insecure bool) error {
	_, err := withServiceSession(b, state, insecure, func(s *session) (ServiceState, error) {
		if !errors.Is(s.checkServiceDeadline(time.Now()), ErrServiceDeadline) {
			return ServiceState{}, ErrState
		}
		return ServiceState{}, s.enforceServiceDeadline(time.Now())
	})
	return err
}

func (s *session) deadlineError(err error) error {
	if deadlineErr := s.enforceServiceDeadline(time.Now()); deadlineErr != nil {
		return deadlineErr
	}
	return err
}
