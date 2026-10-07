//go:build linux

package packagehelper

import (
	"context"
	"localrmm/internal/actionpermit"
	"localrmm/internal/mutationfence"
	"localrmm/internal/nativeapt"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"os"
	"time"
)

type runner struct {
	fs       protectedFS
	fence    fence
	commands commands
	now      func() time.Time
	load     func() (authority, error)
	identity func() (int, string, error)
}

func processSelf() (int, string, error) {
	_, s, e := procIdentity(os.Getpid())
	return os.Getpid(), s, e
}
func resultFor(plan packageplan.Plan, seq uint64, phase string, now int64, reason string, state *dpkgState, reboot string) packageupdate.Result {
	dpkg := "unknown"
	if state != nil {
		dpkg = "clean"
	}
	return packageupdate.Result{Sequence: seq, Phase: phase, ObservedAt: now, Packages: packageRows(plan, state), Reboot: packageupdate.RebootEvidence{State: reboot, Source: "native", ObservedAt: now}, DpkgState: dpkg, Reason: reason}
}
func (r runner) run(id string) error {
	if _, e := nativeapt.JobPaths(id); e != nil {
		return e
	}
	a, e := r.load()
	if e != nil || !a.policy.Enabled {
		return ErrRejected
	}
	if e = checkState(r.fs, a); e != nil {
		return e
	}
	mode := "prepare"
	exists, e := r.fs.exists(jobFile(id, "execute.admitted"))
	if e != nil {
		return e
	}
	if exists {
		mode = "execute"
	}
	raw, p, e := readPermit(r.fs, id, mode)
	if e != nil {
		return e
	}
	now := r.now().Unix()
	if _, e = packagepermit.Verify(context.Background(), raw, a.pins(), now); e != nil {
		return e
	}
	var adm admission
	if e = r.fs.json(jobFile(id, mode+".admitted"), 4096, &adm); e != nil || adm.EnvelopeDigest != actionpermit.Digest(raw) || adm.At > now {
		return ErrRejected
	}
	entry, e := r.fence.Status(context.Background(), owner(p, raw))
	if e != nil || entry.CompletedAt != 0 || entry.AdmittedAt != adm.At {
		return ErrRejected
	}
	pid, start, e := r.identity()
	if e != nil {
		return e
	}
	// A create-only claim is the last admission before any subprocess. A second
	// process, restart, crash recovery or direct command never receives new rights.
	if e = r.fs.createJSON(jobFile(id, mode+".claim"), runnerClaim{mode, pid, start, now}); e != nil {
		return ErrConflict
	}
	if mode == "prepare" {
		return r.prepare(a, raw, p)
	}
	return r.execute(a, raw, p)
}
func (r runner) refusePreparation(raw []byte, p packagepermit.Permit) error {
	now := r.now().Unix()
	if e := r.fs.createJSON(jobFile(p.JobID, "prepare.failed"), admission{actionpermit.Digest(raw), now}); e != nil {
		return e
	}
	if e := r.fence.Complete(context.Background(), owner(p, raw), "not_started", now); e != nil {
		return e
	}
	return ErrRejected
}
func (r runner) preparedInvocation(p packagepermit.Permit) (nativeapt.Prepared, nativeapt.Invocation, error) {
	b, e := loadPrepared(r.fs, p.JobID)
	if e != nil || !selectedMatches(p, b) || r.fs.checkPrepared(b) != nil {
		return b, nativeapt.Invocation{}, ErrRejected
	}
	inv, e := invocation(p.JobID, b)
	return b, inv, e
}
func (r runner) aptStarted(id, mode string) func(int) error {
	return func(pid int) error {
		_, start, e := procIdentity(pid)
		if e != nil {
			return e
		}
		return r.fs.createJSON(jobFile(id, mode+".apt"), processRecord{pid, start, mode})
	}
}
func (r runner) prepare(a authority, raw []byte, p packagepermit.Permit) error {
	res, e := r.commands.run(commandSpec{nativeapt.NativeExecutable, []string{p.JobID}, nativeapt.Environment(p.JobID), 20 * time.Minute, nil})
	if e != nil || res.exit != 0 {
		return r.refusePreparation(raw, p)
	}
	b, inv, e := r.preparedInvocation(p)
	if e != nil {
		return r.refusePreparation(raw, p)
	}
	latest, e := r.load()
	if e != nil || !a.same(latest) || !latest.policy.Enabled {
		return r.refusePreparation(raw, p)
	}
	res, e = r.commands.run(commandSpec{inv.Executable, inv.Args, inv.Env, 20 * time.Minute, r.aptStarted(p.JobID, "prepare")})
	// apt-get exit 100 alone is NEVER evidence. A complete guard receipt, full raw
	// hook, matching preview and consumed guard occurrence are mandatory.
	if !res.started || res.exit == 0 {
		return r.refusePreparation(raw, p)
	}
	var receipt captureReceipt
	if e = r.fs.json(jobFile(p.JobID, "capture.receipt"), packageplanMaxBytes, &receipt); e != nil || receipt.Version != "tracebolt.apt-capture-receipt.v1" || receipt.PreparationEnvelopeDigest != actionpermit.Digest(raw) {
		return r.refusePreparation(raw, p)
	}
	hook, e := r.fs.read(jobFile(p.JobID, "capture.hook"), packageplan.MaxHookBytes)
	if e != nil || receipt.HookDigest != actionpermit.Digest(hook) {
		return r.refusePreparation(raw, p)
	}
	var apt, once processRecord
	if r.fs.json(jobFile(p.JobID, "prepare.apt"), 4096, &apt) != nil || r.fs.json(jobFile(p.JobID, "prepare.hook-once"), 4096, &once) != nil || !rawEqual(apt, once) || apt.PID != receipt.APTPID || apt.Start != receipt.APTStart {
		return r.refusePreparation(raw, p)
	}
	now := r.now().Unix()
	observed, e := archiveObservations(r.fs, b)
	if e != nil || packageplan.Match(context.Background(), receipt.Preview.Plan, now, hook, observed) != nil || receipt.Preview.Plan.RootPolicyDigest != a.digest || receipt.Preview.RequestID != p.JobID || receipt.Preview.ActorID != p.ActorID {
		return r.refusePreparation(raw, p)
	}
	latest, e = r.load()
	if e != nil || !a.same(latest) || !latest.policy.Enabled || r.fs.checkPrepared(b) != nil {
		return r.refusePreparation(raw, p)
	}
	// Keep preview hidden until capture process has returned and the mutation
	// fence was durably completed; publication never implies native execution.
	if e = r.fence.Complete(context.Background(), owner(p, raw), "not_started", now); e != nil {
		return e
	}
	return r.fs.createJSON(jobFile(p.JobID, "preview.json"), receipt.Preview)
}
func (r runner) unknown(p packagepermit.Permit, reason string) error {
	return r.intervention(p, reason, nil)
}
func (r runner) intervention(p packagepermit.Permit, reason string, state *dpkgState) error {
	if p.Plan == nil {
		return ErrRejected
	}
	s, e := r.fs.snapshot(p.JobID)
	if e != nil {
		return e
	}
	seq := uint64(len(s.Results) + 1)
	if s.State == packageupdate.NeedsIntervention || s.State == packageupdate.Succeeded {
		return ErrConflict
	}
	if e = r.fs.appendResult(p.JobID, resultFor(*p.Plan, seq, packageupdate.NeedsIntervention, r.now().Unix(), reason, state, "unknown")); e != nil {
		return e
	}
	return ErrUncertain
}
func (r runner) execute(a authority, raw []byte, p packagepermit.Permit) error {
	if p.Plan == nil {
		return ErrRejected
	}
	_, inv, e := r.preparedInvocation(p)
	if e != nil {
		return r.unknown(p, "runner_state_unknown")
	}
	latest, e := r.load()
	if e != nil || !a.same(latest) || !latest.policy.Enabled {
		return r.unknown(p, "runner_state_unknown")
	}
	if _, e = packagepermit.Verify(context.Background(), raw, latest.pins(), r.now().Unix()); e != nil {
		return r.unknown(p, "runner_state_unknown")
	}
	// Applying has NO context, timeout or cancellation inherited from the agent,
	// socket request or manager. systemd's independent unit owns the lifetime.
	res, e := r.commands.run(commandSpec{inv.Executable, inv.Args, inv.Env, 0, r.aptStarted(p.JobID, "execute")})
	if e != nil || !res.started || res.exit != 0 {
		return r.unknown(p, "runner_state_unknown")
	}
	var admitted admission
	if e = r.fs.json(jobFile(p.JobID, "execute.guard-admitted"), 4096, &admitted); e != nil || admitted.EnvelopeDigest != actionpermit.Digest(raw) {
		return r.unknown(p, "runner_state_unknown")
	}
	s, e := r.fs.snapshot(p.JobID)
	if e != nil || len(s.Results) != 1 || s.State != packageupdate.Applying {
		return r.unknown(p, "runner_state_unknown")
	}
	if e = r.fs.appendResult(p.JobID, resultFor(*p.Plan, 2, packageupdate.Verifying, r.now().Unix(), "native_running", nil, "unknown")); e != nil {
		return e
	}
	// Reacquire both ordinary dpkg locks for verification. Never delete locks,
	// terminate other managers, run repair, retry, rollback, or reboot.
	frontend, _, e := r.fs.nativeLock("lock-frontend", true)
	if e != nil {
		return r.unknown(p, "runner_state_unknown")
	}
	defer frontend.Close()
	inner, _, e := r.fs.nativeLock("lock", true)
	if e != nil {
		return r.unknown(p, "runner_state_unknown")
	}
	defer inner.Close()
	state, e := r.fs.dpkg()
	if e != nil {
		return r.unknown(p, "verification_mismatch")
	}
	rows := packageRows(*p.Plan, &state)
	for _, v := range rows {
		if v.Outcome != "verified" {
			return r.intervention(p, "verification_mismatch", &state)
		}
	}
	now := r.now().Unix()
	reboot := r.reboot()
	verified := resultFor(*p.Plan, 3, packageupdate.Succeeded, now, "native_verified", &state, reboot)
	if e = r.fs.createJSON(jobFile(p.JobID, "verified.receipt"), verified); e != nil {
		return e
	}
	if e = r.fence.Complete(context.Background(), owner(p, raw), "completed", now); e != nil {
		return r.intervention(p, "runner_state_unknown", &state)
	}
	return r.fs.appendResult(p.JobID, verified)
}
func (r runner) reboot() string {
	_, e := r.fs.read("/run/reboot-required", 64<<10)
	if os.IsNotExist(e) {
		return "not_reported"
	}
	if e != nil {
		return "unknown"
	}
	return "required"
}

// RunRunner is a fixed-unit entry point. Its job ID is the only argument. It
// does not infer success/retry from process restart or missing result files.
func RunRunner(id string) error {
	if rootIdentity() != nil {
		return ErrRejected
	}
	fs := hostFS()
	a, e := fs.authority()
	if e != nil {
		return e
	}
	c := realCommands{}
	if e = checkServiceGeneration(c, a); e != nil {
		return e
	}
	f, e := mutationfence.Open(context.Background(), mutationfence.DefaultDirectory, binding(a))
	if e != nil {
		return e
	}
	defer f.Close()
	return (runner{fs, f, c, time.Now, fs.authority, processSelf}).run(id)
}
