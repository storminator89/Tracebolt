package enrollmentclient

import (
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"localrmm/internal/renewalidentity"
	"path/filepath"
	"time"
)

// RunRenewableForeground is the service scheduler for a fresh explicit renewable
// identity. The old sender remains the sole owner of every pending byte/floor.
// Before credential activation, its context is ended and every helper/action
// worker and protected-store lock is joined and closed by RunForeground.
// A cutover never re-signs, relabels, resets or initializes sender state.
func RunRenewableForeground(ctx context.Context, configPath string, interval time.Duration, observe func(agentloop.Event) error) (agentloop.Summary, error) {
	if ctx == nil {
		return agentloop.Summary{}, ErrState
	}
	raw, e := lanconfig.ReadProtected(configPath, true, 16384)
	if e != nil {
		return agentloop.Summary{}, ErrState
	}
	var c lanclient.Config
	if strictJSON(raw, &c) != nil || c.Validate() != nil {
		return agentloop.Summary{}, ErrState
	}
	if c.RenewalManifestFile == "" {
		m, e := lanclient.Load(configPath)
		if e != nil {
			return agentloop.Summary{}, e
		}
		return lanclient.RunForeground(ctx, m, interval, observe)
	}
	state := filepath.Dir(configPath)
	if c.RenewalManifestFile != filepath.Join(state, renewalidentity.ManifestName) || c.CertificateFile != filepath.Join(state, "agent-cert.pem") || c.PrivateKeyFile != filepath.Join(state, "agent-key.pem") || c.StateDirectory != filepath.Join(state, "telemetry") {
		return agentloop.Summary{}, ErrState
	}
	return runRenewalScheduler(ctx, renewalSchedulerDependencies{
		cycle: func(ctx context.Context, activate bool) (time.Duration, error) {
			return runRenewalCycleMode(ctx, state, activate)
		},
		sender: func(ctx context.Context) (agentloop.Summary, error) {
			m, e := lanclient.Load(configPath)
			if e != nil {
				return agentloop.Summary{}, e
			}
			if !m.AutomaticRenewal() {
				return agentloop.Summary{}, ErrState
			}
			return lanclient.RunForeground(ctx, m, interval, observe)
		},
	})
}

var errRenewalCutover = errors.New("renewal candidate requires joined sender cutover")

type renewalSchedulerDependencies struct {
	cycle  func(context.Context, bool) (time.Duration, error)
	sender func(context.Context) (agentloop.Summary, error)
}
type renewalSenderResult struct {
	summary agentloop.Summary
	err     error
}

func runRenewalScheduler(ctx context.Context, d renewalSchedulerDependencies) (agentloop.Summary, error) {
	var summary agentloop.Summary
	if ctx == nil || d.cycle == nil || d.sender == nil {
		return summary, ErrState
	}
	appendResult := func(next agentloop.Summary) {
		summary.Attempts += next.Attempts
		summary.LastOutcome = next.LastOutcome
		summary.ConsecutiveFailures = next.ConsecutiveFailures
		summary.Reason = next.Reason
	}
	for ctx.Err() == nil {
		delay, e := d.cycle(ctx, true)
		if e != nil {
			return summary, e
		}
		if delay <= 0 || delay > 7*24*time.Hour {
			return summary, ErrState
		}
		run, cancel := context.WithCancel(ctx)
		done := make(chan renewalSenderResult, 1)
		go func() { s, e := d.sender(run); done <- renewalSenderResult{s, e} }()
		timer := time.NewTimer(delay)
		join := func() renewalSenderResult {
			timer.Stop()
			cancel()
			result := <-done
			appendResult(result.summary)
			return result
		}
		cutover := false
		for !cutover {
			select {
			case <-ctx.Done():
				join()
				return summary, ctx.Err()
			case result := <-done:
				timer.Stop()
				cancel()
				appendResult(result.summary)
				return summary, result.err
			case <-timer.C:
				// Preparation may run while collection continues. It cannot activate or
				// publish a new credential. An unchanged/retrying check leaves memory-only
				// results and provider samplers alive with their original expiration.
				delay, e = d.cycle(ctx, false)
				if errors.Is(e, errRenewalCutover) {
					result := join()
					if result.err != nil && !errors.Is(result.err, context.Canceled) && !errors.Is(result.err, context.DeadlineExceeded) {
						return summary, result.err
					}
					cutover = true
				} else if e != nil {
					join()
					return summary, e
				} else if delay <= 0 || delay > 7*24*time.Hour {
					join()
					return summary, ErrState
				} else {
					timer.Reset(delay)
				}
			}
		}
	}
	return summary, ctx.Err()
}

func runRenewalCycle(ctx context.Context, state string) (time.Duration, error) {
	return runRenewalCycleMode(ctx, state, true)
}
func runRenewalCycleMode(ctx context.Context, state string, activate bool) (time.Duration, error) {
	st, e := openEnrollmentStore(state, true, true)
	if e != nil {
		return 0, e
	}
	defer st.Close()
	raw, e := st.Read("ledger.json")
	if e != nil {
		return 0, ErrState
	}
	var l ledger
	if strictJSON(raw, &l) != nil || l.Version != renewableLedgerVersion || l.Bootstrap.RenewalPolicy != renewalidentity.Policy || !l.Activated || !l.HandoffPrepared || !l.SenderInitializationStarted {
		return 0, ErrState
	}
	s := &session{&sessionData{store: st, opts: Options{StateDirectory: state, ResumeOnly: true, renewalReconcile: true, inventoryEnrollment: l.MacOSInventory != nil, inventoryAuthorityReading: l.MacOSInventory != nil}}}
	defer func() { clear(s.key) }()
	if e = s.load(l.Bootstrap); e != nil {
		return 0, e
	}
	raw, e = st.Read(renewalidentity.ManifestName)
	if e != nil {
		return 0, ErrState
	}
	m, e := renewalidentity.Parse(raw)
	if e != nil || s.validateRenewalManifestAt(m, time.Now(), true) != nil {
		return 0, ErrState
	}
	tx, e := s.loadRenewalTransaction(m)
	if e != nil {
		return 0, e
	}
	if !s.l.RenewalReadyPublished {
		return 0, ErrState
	}
	if activate {
		c, files, _, err := s.handoff()
		clearArtifacts(files)
		anchor, decodeErr := decode64(s.l.CertificateDER, 8192)
		validSender := func() bool {
			if s.l.MacOSInventory != nil {
				c, _, enable, e := s.macOSInventoryOriginal()
				return e == nil && validateMacOSInventoryStorage(c.StateDirectory, enable) == nil
			}
			return lanclient.ValidateRenewalSenderState(c, anchor) == nil
		}
		if err != nil || decodeErr != nil || !validSender() {
			return 0, ErrState
		}
	}
	// Persisted backoff is consulted even with a staged transaction; process
	// restarts cannot create a tight retry storm or replace an uncertain request.
	if tx.NextAttemptAt > time.Now().Unix() {
		return time.Until(time.Unix(tx.NextAttemptAt, 0)), nil
	}
	client, e := newEnrollmentHTTPClient(s.l.Bootstrap)
	if e != nil {
		return 0, e
	}
	defer client.CloseIdleConnections()
	s.wire = &wireClient{client: client, origin: s.l.Bootstrap.EnrollmentOrigin, collectionProfile: s.l.Bootstrap.CollectionProfile}
	attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	e = s.renewOncePrepared(attempt, m, &tx, activate)
	if e == nil {
		current, readErr := s.loadRenewalManifest()
		if readErr != nil {
			return 0, readErr
		}
		due := renewalDue(current)
		if delay := time.Until(due); delay > 0 {
			return delay, nil
		}
		return 5 * time.Minute, nil
	}
	if errors.Is(e, errRenewalCutover) {
		return 0, e
	}
	if errors.Is(e, ErrState) || errors.Is(e, ErrResponse) {
		return 0, e
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if tx.State == "revoked" {
		return 0, ErrTerminal
	}
	if time.Now().Unix() >= m.Intent.NotAfter {
		return 0, ErrTerminal
	}
	if tx.Failures < 32 {
		tx.Failures++
	}
	// Stable identity/generation jitter avoids synchronized fleets without a
	// fresh RNG dependency or permitting unbounded/backward retry delays.
	shift := min(tx.Failures, uint64(4))
	seconds := int64(15) * (1 << shift)
	if seconds > 240 {
		seconds = 240
	}
	seconds += int64(m.CertificateDER[len(m.CertificateDER)-1] % 31)
	if tx.State != "blocked" {
		tx.State = "retrying"
	}
	tx.NextAttemptAt = time.Now().Unix() + seconds
	if e = s.saveRenewalTransaction(tx); e != nil {
		return 0, e
	}
	return time.Duration(seconds) * time.Second, nil
}

// PrepareServiceRenewal reconciles only a previously activated renewable
// identity before the read-only service handoff preflight. A pending first
// enrollment remains untouched. In particular this cannot claim or initialize.
func PrepareServiceRenewal(ctx context.Context, b Bootstrap, state string) error {
	if b.RenewalPolicy == "" {
		return nil
	}
	st, e := openEnrollmentStore(state, true, true)
	if e != nil {
		return e
	}
	raw, e := st.Read("ledger.json")
	if e != nil {
		st.Close()
		return ErrState
	}
	var l ledger
	if strictJSON(raw, &l) != nil || l.Version != renewableLedgerVersion || l.Bootstrap != b {
		st.Close()
		return ErrState
	}
	active := l.Activated && l.HandoffPrepared && l.SenderInitializationStarted && l.RenewalReadyPublished
	if e = st.Close(); e != nil {
		return e
	}
	if !active {
		return nil
	}
	_, e = runRenewalCycle(ctx, state)
	return e
}
