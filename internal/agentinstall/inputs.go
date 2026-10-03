package agentinstall

import "context"

// VerifiedInputs owns only read-only source descriptors. Digests are selected by
// the operator from a trusted release/reference; this is not signature proof.
type VerifiedInputs struct {
	Agent, Enrollment *VerifiedArtifact
	SourceSHA256      string
}

func (v *VerifiedInputs) Close() {
	if v == nil {
		return
	}
	v.Agent.Close()
	v.Enrollment.Close()
}
func VerifyInputs(ctx context.Context, r Request) (*VerifiedInputs, error) {
	if r.Action != Install && r.Action != Upgrade {
		return nil, ErrContract
	}
	if !validInputPath(r.SourceArchive) || VerifySource(ctx, r.SourceArchive, r.SourceSHA256) != nil {
		return nil, ErrArtifact
	}
	agent, e := VerifyBinary(ctx, r.AgentBinary, r.AgentSHA256, SenderBinary)
	if e != nil {
		return nil, e
	}
	enrollment, e := VerifyBinary(ctx, r.EnrollBinary, r.EnrollSHA256, EnrollmentBinary)
	if e != nil {
		agent.Close()
		return nil, e
	}
	return &VerifiedInputs{Agent: agent, Enrollment: enrollment, SourceSHA256: r.SourceSHA256}, nil
}
