// Package windowssoftwareexecutor owns the single native MSI call inside a
// separately authorized foreground executor. Construction grants no authority;
// observation workers and service brokers cannot import or dispatch it.
package windowssoftwareexecutor

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	"localrmm/internal/windowspackage"
	job "localrmm/internal/windowssoftwarejob"
)

var (
	ErrUnavailable = errors.New("windows_software_executor_unavailable")
	ErrIdentity    = errors.New("windows_software_executor_exact_identity_unproven")
	ErrOffline     = errors.New("windows_software_executor_offline_unproven")
	ErrReadiness   = errors.New("windows_software_executor_readiness_unproven")
	ErrSettings    = errors.New("windows_software_executor_installer_safeguards_unproven")
	ErrUncertain   = errors.New("windows_software_executor_outcome_uncertain")
	ErrClosed      = errors.New("windows_software_executor_closed_or_consumed")
)

// These bound the caller's wait, not MSI execution. The 60-second signed start
// deadline is enforced by windowssoftwarejob. It is not an installation duration.
const (
	preparationLimit  = 30 * time.Second
	installationLimit = 30 * time.Minute
	idleLimit         = 60 * time.Second
	closeLimit        = time.Second
)

type Adapter struct {
	maintenanceUntil                      int64
	checkStart                            func(context.Context, time.Time) error
	mu                                    sync.Mutex
	busy, uncertain                       bool
	open                                  func(context.Context) (nativeRuntime, error)
	now                                   func() time.Time
	prepareLimit, installLimit, idleLimit time.Duration
}

// New constructs an inert adapter. Only a future, separately provisioned
// dedicated administrator-capable executor may supply it to OpenExecutor.
// PrepareExact is the first native access; the default kernel remains inactive.
func New(consent job.Consent, receipt windowspackage.PreparedMSIReceipt, maintenanceUntil time.Time) (*Adapter, error) {
	now := time.Now().UTC()
	if consent.Validate() != nil || !consent.Enabled || !consent.Acknowledged || !consent.PackageReviewAccepted || receipt.Validate() != nil || receipt.Package != consent.Package || maintenanceUntil.Unix() <= now.Unix() || maintenanceUntil.Sub(now) > 10*time.Minute {
		return nil, job.ErrAuthority
	}
	a := newAdapter(func(ctx context.Context) (nativeRuntime, error) { return openNative(ctx, consent, receipt) }, time.Now)
	a.maintenanceUntil = maintenanceUntil.UTC().Unix()
	return a, nil
}
func newAdapter(open func(context.Context) (nativeRuntime, error), now func() time.Time) *Adapter {
	return &Adapter{checkStart: job.CheckInstallStart, open: open, now: now, prepareLimit: preparationLimit, installLimit: installationLimit, idleLimit: idleLimit}
}

var _ job.ExecutorAdapter = (*Adapter)(nil)
var _ job.PreparedPackage = (*prepared)(nil)

type reply struct {
	readiness job.Readiness
	result    job.NativeResult
	err       error
}
type request struct {
	ctx     context.Context
	install bool
	reply   chan reply
	settled chan struct{}
}
type prepared struct {
	readySettled                         chan struct{}
	owner                                *Adapter
	requests                             chan request
	stop, done                           chan struct{}
	stopOnce                             sync.Once
	mu                                   sync.Mutex
	active, installed, closed, abandoned bool
	closeErr                             error
}

func (a *Adapter) poison() { a.mu.Lock(); a.uncertain = true; a.mu.Unlock() }
func (a *Adapter) PrepareExact(ctx context.Context, selection job.Selection) (job.PreparedPackage, error) {
	if ctx == nil || !job.ValidSelection(selection) || a == nil || a.open == nil || a.now == nil {
		return nil, job.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.busy || a.uncertain {
		a.mu.Unlock()
		return nil, ErrClosed
	}
	a.busy = true
	a.mu.Unlock()
	p := &prepared{owner: a, requests: make(chan request), stop: make(chan struct{}), done: make(chan struct{}), readySettled: make(chan struct{})}
	defer close(p.readySettled)
	bounded, cancel := context.WithTimeout(ctx, a.prepareLimit)
	defer cancel()
	ready := make(chan error, 1)
	go p.run(bounded, selection, ready)
	select {
	case err := <-ready:
		if err != nil {
			p.abort()
			return nil, err
		}
		if err = bounded.Err(); err != nil {
			p.abort()
			return nil, err
		}
		return p, nil
	case <-bounded.Done():
		p.abort()
		return nil, bounded.Err()
	}
}

// The worker owns custody handles, token checks and MSI calls on one OS thread.
// Neither cancellation nor Close releases custody while a native call uses it.
func (p *prepared) run(ctx context.Context, selection job.Selection, ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		p.owner.mu.Lock()
		p.owner.busy = false
		// Completion and admission release form one atomic state transition.
		close(p.done)
		p.owner.mu.Unlock()
	}()
	publishReady := func(err error) bool {
		// Poison on the owner before any failing publication or busy release.
		// The caller can be descheduled after a buffered send indefinitely.
		if err != nil {
			p.owner.poison()
		}
		ready <- err
		select {
		case <-p.readySettled:
			return err == nil
		case <-p.stop:
			return false
		}
	}
	if err := ctx.Err(); err != nil {
		publishReady(err)
		return
	}
	native, err := p.owner.open(ctx)
	if err != nil {
		publishReady(err)
		return
	}
	defer func() {
		err := native.close()
		p.mu.Lock()
		p.closeErr = err
		p.mu.Unlock()
		if err != nil {
			p.owner.poison()
		}
	}()
	e := &engine{native: native, selection: selection, now: p.owner.now, checkStart: p.owner.checkStart, maintenanceUntil: p.owner.maintenanceUntil}
	if err = e.prepare(ctx); err != nil {
		publishReady(err)
		return
	}
	if !publishReady(nil) {
		return
	}
	timer := time.NewTimer(p.owner.idleLimit)
	defer timer.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-timer.C:
			return
		case r := <-p.requests:
			// The idle deadline never truncates an already running installation.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			var out reply
			if err := r.ctx.Err(); err != nil {
				out.err = err
			} else if r.install {
				out.result, out.err = e.installOnce(r.ctx)
			} else {
				out.readiness, out.err = e.inspect(r.ctx)
				if out.err == nil {
					e.reviewed = &out.readiness
				}
			}
			// A late native reply does not overwrite the caller's uncertainty.
			if err := r.ctx.Err(); err != nil {
				out.err = err
			}
			if r.install && (out.err != nil || out.result.ReturnCode != 0 || out.result.RegistrationVerified != job.Yes) {
				p.owner.poison()
			}
			r.reply <- out
			// Do not free admission until the caller has decided whether this
			// reply is timely or abandoned and finalized its poison decision.
			select {
			case <-r.settled:
			case <-p.stop:
				return
			}
			if out.err != nil || r.install {
				return
			}
			timer.Reset(p.owner.idleLimit)
		}
	}
}

// poisonIfUnfinished settles uncertainty against this owner's completion under
// the admission lock. Stale handles and delayed timers cannot poison a later
// owner after this one's completed slot has been reused.
func (p *prepared) poisonIfUnfinished() bool {
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	select {
	case <-p.done:
		return false
	default:
		p.owner.uncertain = true
		return true
	}
}
func (p *prepared) abort() {
	p.mu.Lock()
	p.abandoned = true
	p.closed = true
	p.mu.Unlock()
	p.poisonIfUnfinished()
	p.stopOnce.Do(func() { close(p.stop) })
}
func (p *prepared) call(ctx context.Context, install bool) reply {
	if ctx == nil {
		return reply{err: job.ErrInvalid}
	}
	p.mu.Lock()
	if p.closed || p.active || p.installed {
		p.mu.Unlock()
		return reply{err: ErrClosed}
	}
	p.active = true
	if install {
		p.installed = true
	}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active = false; p.mu.Unlock() }()
	if err := ctx.Err(); err != nil {
		if install {
			p.poisonIfUnfinished()
		}
		return reply{err: err}
	}
	limit := p.owner.prepareLimit
	if install {
		limit = p.owner.installLimit
	}
	bounded, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	r := request{ctx: bounded, install: install, reply: make(chan reply, 1), settled: make(chan struct{})}
	defer close(r.settled)
	select {
	case p.requests <- r:
	case <-p.done:
		return reply{err: ErrClosed}
	case <-p.stop:
		return reply{err: ErrClosed}
	case <-bounded.Done():
		p.abort()
		return reply{err: bounded.Err()}
	}
	select {
	case out := <-r.reply:
		if bounded.Err() != nil {
			p.abort()
			return reply{err: bounded.Err()}
		}
		if install && out.err != nil {
			p.poisonIfUnfinished()
		}
		return out
	case <-p.stop:
		p.poisonIfUnfinished()
		return reply{err: ErrUncertain}
	case <-bounded.Done():
		p.abort()
		return reply{err: bounded.Err()}
	}
}
func (p *prepared) Inspect(ctx context.Context) (job.Readiness, error) {
	r := p.call(ctx, false)
	return r.readiness, r.err
}
func (p *prepared) InstallOnce(ctx context.Context) (job.NativeResult, error) {
	r := p.call(ctx, true)
	return r.result, r.err
}
func (p *prepared) Close() error {
	p.mu.Lock()
	active, abandoned := p.active, p.abandoned
	p.closed = true
	p.mu.Unlock()
	if active || abandoned {
		// Closing stop lets the owner exit. Finalize poison before that can
		// release admission to a concurrent PrepareExact caller.
		unfinished := p.poisonIfUnfinished()
		p.stopOnce.Do(func() { close(p.stop) })
		if unfinished {
			return ErrUncertain
		}
		return nil
	}
	p.stopOnce.Do(func() { close(p.stop) })
	timer := time.NewTimer(closeLimit)
	defer timer.Stop()
	select {
	case <-p.done:
		p.mu.Lock()
		err := p.closeErr
		p.mu.Unlock()
		return err
	case <-timer.C:
		// A timer can fire while this caller is descheduled and completion can
		// win before it resumes. Settle under the same admission mutex: never
		// poison a completed owner after its slot has been reused.
		if p.poisonIfUnfinished() {
			return ErrUncertain
		}
		return nil
	}
}
