package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
)

const CoordinatedExecutorVersion = "tracebolt.windows-selected-update-executor.v2"

func MutationParticipant(c Consent) fence.Participant {
	b, _ := json.Marshal(c.Binding)
	raw, _ := json.Marshal(c)
	return fence.Participant{Domain: fence.CachedWUA, BindingDigest: actionpermit.Digest(b), GrantDigest: actionpermit.Digest(raw), ManagerKeyDigest: c.Binding.KeyID, ExecutorKeyDigest: c.Binding.ExecutorKeyID}
}
func ValidMutationRoster(r *fence.Roster, c Consent) bool {
	if r == nil || r.Validate() != nil || (c.Version != CoordinatedConsentVersion && !c.Background()) || c.Background() != (r.Version == fence.BackgroundRosterVersion) || c.Validate() != nil {
		return false
	}
	b := c.Binding
	return r.Plan.Identity == (fence.Identity{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest}) && r.Plan.PlanDigest == c.MutationPlanDigest && c.PeerBindingDigest == r.MSI.BindingDigest && r.WUA == MutationParticipant(c)
}
func NewCoordinatedExecutorRecord(c Consent, manager, executor ed25519.PublicKey, at int64, roster fence.Roster) (ExecutorRecord, error) {
	r := ExecutorRecord{Version: Version, Consent: c, PublicKey: append([]byte(nil), manager...), ExecutorPublicKey: append([]byte(nil), executor...), ClockFloor: at, Attempts: []Attempt{}}
	r.Version = CoordinatedExecutorVersion
	r.Mutation = &roster
	return r, r.Validate()
}

func mutationOwner(p Permit, raw []byte) fence.Owner {
	return fence.Owner{Domain: fence.CachedWUA, JobID: p.Preview.ID, Sequence: p.Sequence, PermitDigest: actionpermit.Digest(raw)}
}
func (r ExecutorRecord) validateMutationCompletion(a Attempt, p Permit) error {
	c := a.MutationCompletion
	if c == nil {
		return nil
	}
	if r.Mutation == nil || c.Validate() != nil || c.FenceID != r.Mutation.FenceID || c.RosterDigest != r.Mutation.Digest() || c.Owner != mutationOwner(p, a.Envelope) || a.Result == nil || !a.Attempted || a.Result.Outcome == "uncertain" || a.Result.Outcome == "not_attempted" || c.ResultDigest != actionpermit.Digest(a.ResultReport) || c.CompletedAt != a.Result.CompletedAt {
		return ErrIntegrity
	}
	return nil
}
func (x *Executor) verifyMutationCompletion(receipt fence.Receipt) error {
	raw, e := x.store.Read("executor.json")
	var r ExecutorRecord
	if e != nil || canonical(raw, &r, MaxBytes) != nil || r.Validate() != nil || !bytes.Equal(raw, x.raw) {
		return ErrIntegrity
	}
	for _, a := range r.Attempts {
		if a.MutationCompletion != nil && *a.MutationCompletion == receipt {
			return nil
		}
	}
	return ErrIntegrity
}

func (r Record) validateMutationReport() error {
	if len(r.MutationReport) == 0 {
		return nil
	}
	s, e := VerifyStatement(r.MutationReport, r.ExecutorPublicKey)
	if e != nil || r.Consent.MutationPlanDigest == "" || s.Kind != "mutation" || s.Binding != r.Consent.Binding || s.IssuedAt > r.ClockFloor || s.ExpiresAt > r.Consent.ExpiresAt {
		return ErrIntegrity
	}
	return nil
}
func CheckMutationTransition(before, after Record) error {
	if len(before.MutationReport) == 0 {
		return nil
	}
	if len(after.MutationReport) == 0 {
		return ErrIntegrity
	}
	a, e := VerifyStatement(before.MutationReport, after.ExecutorPublicKey)
	b, be := VerifyStatement(after.MutationReport, after.ExecutorPublicKey)
	if e != nil || be != nil || b.IssuedAt < a.IssuedAt || b.Mutation.Revision < a.Mutation.Revision || b.Mutation.Revision == a.Mutation.Revision && *b.Mutation != *a.Mutation {
		return ErrIntegrity
	}
	return nil
}
