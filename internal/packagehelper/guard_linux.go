//go:build linux

package packagehelper

import (
	"context"
	"io"
	"localrmm/internal/actionpermit"
	"localrmm/internal/mutationfence"
	"localrmm/internal/nativeapt"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"os"
	"time"
)

const CaptureAbortExit = 42

func loadPrepared(fs protectedFS, id string) (nativeapt.Prepared, error) {
	raw, e := fs.read(jobFile(id, "prepared.json"), nativeapt.MaxBundleBytes)
	if e != nil {
		return nativeapt.Prepared{}, e
	}
	return nativeapt.DecodePrepared(context.Background(), raw, id)
}
func invocation(id string, b nativeapt.Prepared) (nativeapt.Invocation, error) {
	ss := make([]nativeapt.ExactSelection, len(b.Packages))
	for i, p := range b.Packages {
		ss[i] = nativeapt.ExactSelection{Name: p.Name, Architecture: p.Architecture, Version: p.To.Version}
	}
	return nativeapt.BuildInvocation(id, ss)
}
func archiveObservations(fs protectedFS, b nativeapt.Prepared) ([]packageplan.ObservedArchive, error) {
	out := make([]packageplan.ObservedArchive, len(b.Archives))
	for i, a := range b.Archives {
		d, n, e := fs.hash(a.Path, int64(packageplan.MaxArchiveBytes))
		if e != nil || d != a.SHA256 || n != a.Size {
			return nil, ErrRejected
		}
		out[i] = packageplan.ObservedArchive{Path: a.Path, SHA256: d, Size: n}
	}
	return out, nil
}
func selectedMatches(p packagepermit.Permit, b nativeapt.Prepared) bool {
	if len(p.Selection) != len(b.Packages) {
		return false
	}
	for i, s := range p.Selection {
		u := b.Packages[i]
		if s.Name != u.Name || s.Architecture != u.Architecture {
			return false
		}
	}
	return true
}

// RunGuard accepts only a validated job ID and APT's bounded v3 stdin. Capture
// ALWAYS fails. Exit 0 is possible only after durable one-use execute admission.
type guard struct {
	fs       protectedFS
	fence    fence
	load     func() (authority, error)
	now      func() time.Time
	identity func(int) (int, string, error)
	prove    func(protectedFS, authority, string, string, nativeapt.Invocation) (processRecord, *os.File, error)
}

func (g guard) run(id string, input io.Reader) int {
	if _, e := nativeapt.JobPaths(id); e != nil {
		return 1
	}
	fs := g.fs
	a, e := g.load()
	if e != nil || !a.policy.Enabled || checkState(fs, a) != nil {
		return 1
	}
	mode := "prepare"
	if exists, e := fs.exists(jobFile(id, "execute.claim")); e != nil {
		return 1
	} else if exists {
		mode = "execute"
	}
	raw, p, e := readPermit(fs, id, mode)
	if e != nil {
		return 1
	}
	p, e = packagepermit.CheckSignature(context.Background(), raw, a.pins())
	if e != nil {
		return 1
	}
	var adm admission
	if e = fs.json(jobFile(id, mode+".admitted"), 4096, &adm); e != nil || adm.EnvelopeDigest != actionpermit.Digest(raw) {
		return 1
	}
	var claim runnerClaim
	if e = fs.json(jobFile(id, mode+".claim"), 4096, &claim); e != nil || claim.Mode != mode {
		return 1
	}
	_, start, e := g.identity(claim.PID)
	if e != nil || start != claim.Start {
		return 1
	}
	b, e := loadPrepared(fs, id)
	if e != nil || !selectedMatches(p, b) || fs.checkPrepared(b) != nil {
		return 1
	}
	inv, e := invocation(id, b)
	if e != nil {
		return 1
	}
	apt, lock, e := g.prove(fs, a, id, mode, inv)
	if e != nil || lock == nil {
		return 1
	}
	defer lock.Close()
	// This create happens before reading/accepting stream bytes, so a malformed or
	// repeated guard can never be retried into success within one APT invocation.
	if e = fs.createJSON(jobFile(id, mode+".hook-once"), apt); e != nil {
		return 1
	}
	hook, e := io.ReadAll(io.LimitReader(input, packageplan.MaxHookBytes+1))
	if e != nil || len(hook) > packageplan.MaxHookBytes {
		return 1
	}
	observed, e := archiveObservations(fs, b)
	if e != nil {
		return 1
	}
	now := g.now().UTC().Unix()
	entry, e := g.fence.Status(context.Background(), owner(p, raw))
	if e != nil || entry.CompletedAt != 0 || entry.AdmittedAt > now {
		return 1
	}
	state, e := fs.dpkg()
	if e != nil {
		return 1
	}
	if mode == "prepare" {
		plan, e := nativeapt.FinalizeCapture(context.Background(), b, nativeapt.Binding{EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, HookPolicyDigest: hookPolicyDigest(a), CreatedAt: now, ExpiresAt: now + 120}, hook, observed)
		if e != nil || validateOld(state, plan) != nil {
			return 1
		}
		ss := make([]packageupdate.Selection, len(p.Selection))
		for i, s := range p.Selection {
			ss[i] = packageupdate.Selection{Name: s.Name, Architecture: s.Architecture}
		}
		sources := make([]packageupdate.Source, len(b.Sources))
		for i, s := range b.Sources {
			sources[i] = packageupdate.Source{IdentityDigest: s.IdentityDigest, Label: s.Label, Suite: s.Suite, Component: s.Component}
		}
		preview, e := packageupdate.DescribePreview(context.Background(), packageupdate.Binding{ManagerID: p.ManagerID, DeviceID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, TransportProfile: a.policy.TransportProfile}, packageupdate.PrepareRequest{RequestID: id, Packages: ss}, p.ActorID, plan, sources)
		if e != nil {
			return 1
		}
		if e = fs.create(jobFile(id, "capture.hook"), hook); e != nil {
			return 1
		}
		receipt := captureReceipt{"tracebolt.apt-capture-receipt.v1", actionpermit.Digest(hook), actionpermit.Digest(raw), apt.PID, apt.Start, now, preview}
		if e = fs.createJSON(jobFile(id, "capture.receipt"), receipt); e != nil {
			return 1
		}
		return CaptureAbortExit
	}
	if _, e = packagepermit.Verify(context.Background(), raw, a.pins(), now); e != nil || p.Plan == nil || p.Plan.Evidence.HookPolicyDigest != hookPolicyDigest(a) || validateOld(state, *p.Plan) != nil {
		return 1
	}
	var preview packageupdate.Preview
	if e = fs.json(jobFile(id, "preview.json"), packageplanMaxBytes, &preview); e != nil || preview.Digest != p.PreviewDigest || preview.PlanDigest != p.PlanDigest || !rawEqual(preview.Plan, p.Plan) {
		return 1
	}
	if e = packageplan.Match(context.Background(), *p.Plan, now, hook, observed); e != nil {
		return 1
	}
	latest, e := g.load()
	if e != nil || !a.same(latest) || !latest.policy.Enabled || fs.checkPrepared(b) != nil {
		return 1
	}
	snapshot, e := fs.snapshot(id)
	if e != nil || reserveOutcomeCapacity(snapshot) != nil {
		return 1
	}
	if e = fs.createJSON(jobFile(id, "execute.guard-admitted"), admission{actionpermit.Digest(raw), now}); e != nil {
		return 1
	}
	if e = fs.appendResult(id, resultFor(*p.Plan, 1, packageupdate.Applying, now, "native_running", nil, "unknown")); e != nil {
		return 1
	}
	return 0
}

func RunGuard(id string, input io.Reader) int {
	if rootIdentity() != nil {
		return 1
	}
	fs := hostFS()
	a, e := fs.authority()
	if e != nil {
		return 1
	}
	f, e := mutationfence.Open(context.Background(), mutationfence.DefaultDirectory, binding(a))
	if e != nil {
		return 1
	}
	defer f.Close()
	return (guard{fs, f, fs.authority, time.Now, procIdentity, proveAPTParent}).run(id, input)
}
