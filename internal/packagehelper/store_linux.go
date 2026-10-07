//go:build linux

package packagehelper

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/mutationfence"
	"localrmm/internal/nativeapt"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageupdate"
	"os"
	"time"
)

type stateBinding struct {
	Version string                `json:"version"`
	Binding mutationfence.Binding `json:"binding"`
}
type admission struct {
	EnvelopeDigest string `json:"envelopeDigest"`
	At             int64  `json:"at"`
}
type runnerClaim struct {
	Mode  string `json:"mode"`
	PID   int    `json:"pid"`
	Start string `json:"start"`
	At    int64  `json:"at"`
}
type captureReceipt struct {
	Version                   string                `json:"version"`
	HookDigest                string                `json:"hookDigest"`
	PreparationEnvelopeDigest string                `json:"preparationEnvelopeDigest"`
	APTPID                    int                   `json:"aptPid"`
	APTStart                  string                `json:"aptStart"`
	At                        int64                 `json:"at"`
	Preview                   packageupdate.Preview `json:"preview"`
}

func binding(a authority) mutationfence.Binding {
	return mutationfence.Binding{ManagerID: a.policy.ManagerID, EndpointID: a.policy.EndpointID, IncarnationDigest: a.policy.IncarnationDigest}
}
func owner(p packagepermit.Permit, raw []byte) mutationfence.Owner {
	return mutationfence.Owner{Action: p.Action, JobID: p.JobID, Sequence: p.Sequence, EnvelopeDigest: actionpermit.Digest(raw)}
}
func checkState(fs protectedFS, a authority) error {
	var b stateBinding
	if e := fs.json(nativeapt.JobRoot+"/binding.json", 4096, &b); e != nil {
		return e
	}
	if b.Version != StateVersion || b.Binding != binding(a) {
		return ErrRejected
	}
	f, _, e := fs.open(nativeapt.JobRoot+"/broker.lock", 1)
	if e != nil {
		return e
	}
	f.Close()
	return nil
}

// Initialize is an explicit administrator provisioning API, never called by a
// runtime or automatically after missing/corrupt state. All directories, policy,
// trust and reviewed updated executables must already exist. It requires stopped
// legacy service helper AND socket before creating either package/fence state.
func Initialize(ctx context.Context) error {
	if rootIdentity() != nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	fs := hostFS()
	a, e := fs.authority()
	if e != nil {
		return e
	}
	if e = checkServiceQuiescent(ctx, realCommands{}); e != nil {
		return e
	}
	for _, n := range []string{"binding.json", "broker.lock"} {
		exists, e := fs.exists(nativeapt.JobRoot + "/" + n)
		if e != nil || exists {
			return ErrConflict
		}
	}
	f, e := mutationfence.Create(ctx, mutationfence.DefaultDirectory, binding(a), time.Now().UTC().Unix())
	if e != nil {
		return e
	}
	defer f.Close()
	if e = fs.createJSON(nativeapt.JobRoot+"/binding.json", stateBinding{StateVersion, binding(a)}); e != nil {
		return e
	}
	return fs.create(nativeapt.JobRoot+"/broker.lock", nil)
}
func readPermit(fs protectedFS, id, mode string) ([]byte, packagepermit.Permit, error) {
	if !enrollmentcrypto.ValidID(id, "update_") || (mode != "prepare" && mode != "execute") {
		return nil, packagepermit.Permit{}, ErrRejected
	}
	raw, e := fs.read(jobFile(id, mode+".permit"), packagepermit.MaxEnvelopeBytes)
	if e != nil {
		return nil, packagepermit.Permit{}, e
	}
	p, _, e := packagepermit.Decode(context.Background(), raw)
	if e != nil || p.JobID != id || (mode == "prepare" && p.Action != packagepermit.Prepare) || (mode == "execute" && p.Action != packagepermit.Execute) {
		return nil, packagepermit.Permit{}, ErrRejected
	}
	return raw, p, nil
}
func (fs protectedFS) snapshot(id string) (Snapshot, error) {
	raw, p, e := readPermit(fs, id, "prepare")
	if e != nil {
		return Snapshot{}, e
	}
	s := Snapshot{Version: SnapshotVersion, JobID: id, Sequence: p.Sequence, PreparationEnvelopeDigest: actionpermit.Digest(raw), State: packageupdate.Preparing, UpdatedAt: p.IssuedAt, Results: []packageupdate.Result{}}
	var adm admission
	if e = fs.json(jobFile(id, "prepare.admitted"), 4096, &adm); e == nil {
		if adm.EnvelopeDigest != s.PreparationEnvelopeDigest || adm.At < p.IssuedAt {
			return s, ErrRejected
		}
		s.UpdatedAt = adm.At
	} else if !os.IsNotExist(e) {
		return s, e
	}
	var preview packageupdate.Preview
	if e = fs.json(jobFile(id, "preview.json"), packageplanMaxBytes, &preview); e == nil {
		s.Preview = &preview
		s.State = packageupdate.PreviewReady
		s.UpdatedAt = preview.Plan.CreatedAt
	} else if !os.IsNotExist(e) {
		return s, e
	}
	var failed admission
	if e = fs.json(jobFile(id, "prepare.failed"), 4096, &failed); e == nil {
		if s.Preview != nil {
			return s, ErrRejected
		}
		s.State = packageupdate.PreparationFailed
		s.UpdatedAt = failed.At
	} else if !os.IsNotExist(e) {
		return s, e
	}
	var interrupted admission
	if e = fs.json(jobFile(id, "prepare.interrupted"), 4096, &interrupted); e == nil {
		if interrupted.EnvelopeDigest != s.PreparationEnvelopeDigest || interrupted.At < s.UpdatedAt {
			return s, ErrRejected
		}
		s.State = packageupdate.NeedsIntervention
		s.UpdatedAt = interrupted.At
	} else if !os.IsNotExist(e) {
		return s, e
	}
	execRaw, execPermit, e := readPermit(fs, id, "execute")
	if e == nil {
		if s.Preview == nil || execPermit.PreviewDigest != s.Preview.Digest || execPermit.Sequence != p.Sequence {
			return s, ErrRejected
		}
		s.ExecutionEnvelopeDigest = actionpermit.Digest(execRaw)
		s.State = packageupdate.DeliveryUnknown
		if execPermit.IssuedAt > s.UpdatedAt {
			s.UpdatedAt = execPermit.IssuedAt
		}
	} else if !os.IsNotExist(e) {
		return s, e
	}
	for i := 1; i <= 8; i++ {
		var r packageupdate.Result
		e = fs.json(jobFile(id, fmt.Sprintf("result-%d.json", i)), 256<<10, &r)
		if os.IsNotExist(e) {
			break
		}
		if e != nil {
			return s, e
		}
		if r.Sequence != uint64(i) || r.ObservedAt < s.UpdatedAt {
			return s, ErrRejected
		}
		s.Results = append(s.Results, r)
		s.State = r.Phase
		s.UpdatedAt = r.ObservedAt
	}
	if len(s.Results) > 0 {
		s.Result = &s.Results[len(s.Results)-1]
	}
	if e = ValidateSnapshot(s); e != nil {
		return s, e
	}
	return s, nil
}

const packageplanMaxBytes = 256 << 10

func (fs protectedFS) appendResult(id string, r packageupdate.Result) error {
	s, e := fs.snapshot(id)
	if e != nil {
		return e
	}
	if r.Sequence != uint64(len(s.Results)+1) || r.ObservedAt < s.UpdatedAt {
		return ErrRejected
	}
	s.Results = append(s.Results, r)
	s.Result = &s.Results[len(s.Results)-1]
	s.State = r.Phase
	s.UpdatedAt = r.ObservedAt
	if ValidateSnapshot(s) != nil {
		return ErrRejected
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 256<<10 {
		return ErrRejected
	}
	body, e := json.Marshal(s)
	if e != nil || len(body) > MaxResponseBytes-1024 {
		return ErrRejected
	}
	return fs.createJSON(jobFile(id, fmt.Sprintf("result-%d.json", r.Sequence)), r)
}
func rawEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return equalBytes(x, y)
}
